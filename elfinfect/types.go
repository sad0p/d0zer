package elfinfect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
)

type impSegments struct {
	noteNdx int
	textNdx int
	dynNdx int 
}

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
	SectionNames []string 
	Phdrs   interface{}
	Dyn     interface{}
	Fh      *os.File
	Payload bytes.Buffer
	impNdx impSegments
	hasTLS bool 
}

type DefaultPayload struct {
	payload32 bytes.Buffer
	payload64 bytes.Buffer
}

type InfectOpts uint8
