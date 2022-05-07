package elfinfect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
)

type enumIdent struct {
	Endianness binary.ByteOrder
	Arch       elf.Class
}

type TargetBin struct {
	Filesz   int64
	Contents []byte
	//tName string
	Ident   []byte
	EIdent  enumIdent
	Hdr     interface{}
	Shdrs   interface{}
	Phdrs   interface{}
	Fh      *os.File
	Payload bytes.Buffer
}
