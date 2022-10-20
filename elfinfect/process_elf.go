package elfinfect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"reflect"
//	"fmt"
)

func (t *TargetBin) IsElf() bool {
	t.Ident = t.Contents[:16]
	return !(t.Ident[0] != '\x7f' || t.Ident[1] != 'E' || t.Ident[2] != 'L' || t.Ident[3] != 'F')
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
		end := int(h.Shentsize) * int(h.Shnum) + int(h.Shoff)
		sr := bytes.NewBuffer(t.Contents[start:end])
		t.Shdrs = make([]elf.Section64, h.Shnum)

		if err := binary.Read(sr, t.EIdent.Endianness, t.Shdrs.([]elf.Section64)); err != nil {
			return err
		}
	}

	if h, ok := t.Hdr.(*elf.Header32); ok {
		start := int(h.Shoff)
		end := int(h.Shentsize) * int(h.Shnum) + int(h.Shoff)
		sr := bytes.NewBuffer(t.Contents[start:end])
		t.Shdrs = make([]elf.Section32, h.Shnum)

		if err := binary.Read(sr, t.EIdent.Endianness, t.Shdrs.([]elf.Section32)); err != nil {
			return err
		}
	}

	return nil
}

func (t *TargetBin) GetSectionNames() error {
	if t.Shdrs == nil {
		return errors.New("Programming error: GetSectionHeaders() must be called before GetSectionNames()")
	}
		
	if h, ok := t.Hdr.(*elf.Header64); ok {
		start := t.Shdrs.([]elf.Section64)[h.Shstrndx].Off
		end := t.Shdrs.([]elf.Section64)[h.Shstrndx].Off + t.Shdrs.([]elf.Section64)[h.Shstrndx].Size
		shstrTabReader := bytes.NewBuffer(t.Contents[start:end])		
		shstrTab := make([]byte, t.Shdrs.([]elf.Section64)[h.Shstrndx].Size)

		if err := binary.Read(shstrTabReader, t.EIdent.Endianness, shstrTab); err != nil {
			return err
		}
		
		t.SectionNames = make([]string, h.Shnum)

		for i, v := range t.Shdrs.([]elf.Section64) {
			t.SectionNames[i] = parseSectionHeaderStringTable(v.Name, shstrTab) 
		}
				
		
	}

	return nil 
}

func parseSectionHeaderStringTable(sIndex uint32, shstrTab []byte) string {
	end := sIndex
	for end < uint32(len(shstrTab)) {
		if shstrTab[end] == 0x0 {
			break
		}
		end++
	}
	return string(shstrTab[sIndex:end])
}

func (t *TargetBin) GetProgramHeaders() error {
	if h, ok := t.Hdr.(*elf.Header64); ok {
		start := h.Phoff
		end := int(h.Phentsize) * int(h.Phnum) + int(h.Phoff)
		pr := bytes.NewBuffer(t.Contents[start:end])
		t.Phdrs = make([]elf.Prog64, h.Phnum)

		if err := binary.Read(pr, t.EIdent.Endianness, t.Phdrs.([]elf.Prog64)); err != nil {
			return err
		}
		
		pHeaders := t.Phdrs.([]elf.Prog64)
		for i := 0; i < len(pHeaders); i++ {
			switch {
			case elf.ProgType(pHeaders[i].Type) == elf.PT_LOAD && (elf.ProgFlag(pHeaders[i].Flags) == (elf.PF_X | elf.PF_R)):
				t.impNdx.textNdx = i
			
			case elf.ProgType(pHeaders[i].Type) == elf.PT_NOTE:
				t.impNdx.noteNdx = i

			case elf.ProgType(pHeaders[i].Type) == elf.PT_DYNAMIC:
				t.impNdx.dynNdx = i

			case elf.ProgType(pHeaders[i].Type) == elf.PT_TLS:
				t.hasTLS = true 
			}
		}
	}

	if h, ok := t.Hdr.(*elf.Header32); ok {
		start := h.Phoff
		end := int(h.Phentsize) * int(h.Phnum) + int(h.Phoff)
		pr := bytes.NewBuffer(t.Contents[start:end])
		t.Phdrs = make([]elf.Prog32, h.Phnum)

		if err := binary.Read(pr, t.EIdent.Endianness, t.Phdrs.([]elf.Prog32)); err != nil {
			return err
		}
		
		pHeaders := t.Phdrs.([]elf.Prog32)
		for i := 0; i < len(pHeaders); i++ {
			switch {
			case elf.ProgType(pHeaders[i].Type) == elf.PT_LOAD && (elf.ProgFlag(pHeaders[i].Flags) == (elf.PF_X | elf.PF_R)):
				t.impNdx.textNdx = i
			
			case elf.ProgType(pHeaders[i].Type) == elf.PT_NOTE:
				t.impNdx.noteNdx = i

			case elf.ProgType(pHeaders[i].Type) == elf.PT_DYNAMIC:
				t.impNdx.dynNdx = i
			}
		}
	}

	return nil
}

func (t *TargetBin) GetDyn() error {
	dynNdx := t.impNdx.dynNdx
	if dynNdx == 0 {
		return errors.New("Error: No Dynamic Segment found")
	}

	if pHeaders, ok := t.Phdrs.([]elf.Prog64); ok {
		start := pHeaders[dynNdx].Off
		end := start + pHeaders[dynNdx].Filesz
		
		var dynEntries []elf.Dyn64
		var currentDynEntry elf.Dyn64
		
		dynSize := uint64(reflect.TypeOf(currentDynEntry).Size())

		s := start
		for s < end {
			dr := bytes.NewBuffer(t.Contents[s : s + dynSize])
			if err := binary.Read(dr, t.EIdent.Endianness, &currentDynEntry); err != nil {
				return err
			}
			dynEntries = append(dynEntries, currentDynEntry)
			
			if elf.DynTag(currentDynEntry.Tag) == elf.DT_NULL {
				break
			}
			s += dynSize
		}
	
		t.Dyn = dynEntries
	}

	if pHeaders, ok := t.Phdrs.([]elf.Prog32); ok {
		start := pHeaders[dynNdx].Off
		end := start + pHeaders[dynNdx].Filesz
		
		var dynEntries []elf.Dyn32
		var currentDynEntry elf.Dyn32
		
		dynSize := uint32(reflect.TypeOf(currentDynEntry).Size())

		s := start
		for s < end {
			dr := bytes.NewBuffer(t.Contents[s : s + dynSize])
			if err := binary.Read(dr, t.EIdent.Endianness, &currentDynEntry); err != nil {
				return err
			}
			dynEntries = append(dynEntries, currentDynEntry)
			
			if elf.DynTag(currentDynEntry.Tag) == elf.DT_NULL {
				break
			}
			s += dynSize 
		}

		t.Dyn = dynEntries
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

func getFileOffset(addr interface{}, phdrs interface{}, offset interface{}) error {
	if pHeaders, ok := phdrs.([]elf.Prog64); ok {
		for _, p := range pHeaders {
			endAddr := p.Vaddr + p.Memsz
			if addr.(uint64) >= p.Vaddr && addr.(uint64) <= endAddr {
				*offset.(*uint64) = addr.(uint64) - p.Vaddr + p.Off
				return nil
			}
		}
	}

	if pHeaders, ok := phdrs.([]elf.Prog32); ok {
		for _, p := range pHeaders {
			endAddr := p.Vaddr + p.Memsz 	
			if addr.(uint32) >= p.Vaddr && addr.(uint32) <= endAddr {
				*offset.(*uint32) = addr.(uint32) - p.Vaddr + p.Off
				return nil
			}
		}
	}
	
	return errors.New("Binary corrupt or possible programming error")
}
