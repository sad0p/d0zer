package elfinfect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"reflect"
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
