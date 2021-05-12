package main
import(
	"fmt"
	"encoding/binary"
	"bytes"
)

func modEpilogue64(pSize int32, pEntry uint64, oEntry uint64) []byte {
	/*
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

	fmt.Println("Shellcode before")
	for _, v := range epilog {
		fmt.Printf("%02x ", v)
	}
	encpSize := make([]byte, 4)   

	var noZeros int //does not count bytes of value 0x00 associated with extension
	var incOff int = 0x12

	var boolean adjustSize
	if ! (pSize <= 0xff) {
		binary.LittleEndian.PutUint32(encpSize, uint32(pSize))
		fmt.Printf("%2x\n", encpSize)
		for _, b := range encpSize {
			fmt.Printf("%02x\n", b)
			if b != 0x00 {
				noZeros++
			}
		}
		incOff += (noZeros - 1) //increase the relative call offset in the beginning of the epilog shellcode
		adjustSize =  true
	}
	fmt.Printf("pSize = %d | pEntry = %d | oEntry = %d\n", pSize, pEntry, oEntry)
	fmt.Println("Num of zeros in pSize ", (noZeros - 4))

	for i := 0; i < 4; i++ {
		fmt.Printf("%x\n", encpSize[i])
	}

	//fmt.Printf("0x%x\n", encpSize[:noZeros])
	if incOff != 0 { 
		binary.LittleEndian.PutUint32(epilog[x64_STUB_CALL_START:], uint32(incOff))
	}
	
	fmt.Println("Shellcode after")
	for _, v := range epilog {
		fmt.Printf("%02x ", v)
	}

	var modEpilog bytes.Buffer
	modEpilog.Write(epilog[:x64_STUB_CALL_END])
	if adjustSize {
		//write sub rax
		modEpilog.Write(epilog[5:9])
		//write 2nd operand
		for(i := 9; i < 13; i++) {
		}
	}
	*/
	var incOff uint32 = 0x12
	encPsize := make([]byte, 4)
	binary.LittleEndian.PutUint32(encPsize, uint32(pSize))
	var numZeros uint32 = 0 
	if ! (pSize <= 0xff) {
		for _, b := range encPsize {
			fmt.Printf("%02x\n", b)
			if b != 0x00 {
				numZeros++
			}
		}
		incOff += (numZeros - 1)
	}

	var shellcode bytes.Buffer;
	shellcode.Write([]byte{0xe8}) //call instruction
	
	//encode the offset
	encOff := make([]byte, 4)
	binary.LittleEndian.PutUint32(encOff, incOff)

	//write offset for call instruction
	shellcode.Write(encOff)

	//write sub rax, encPsize
	shellcode.Write([]byte{0x48, 0x83, 0xe8})
	shellcode.Write(encPsize)

	//write sub rax, pEntry
	encPentry := make([]byte, 4)
	binary.LittleEndian.PutUint32(encPentry, uint32(pEntry))
	shellcode.Write([]byte{0x48, 0x2d})
	shellcode.Write(encPentry)

	//write add rax, oEntry
	encOentry := make([]byte, 4)
	binary.LittleEndian.PutUint32(encOentry, uint32(oEntry))
	shellcode.Write([]byte{0x48, 0x05})
	shellcode.Write(encOentry)

	
	/* --- write -- */
	//jmp rax
	//mov rax, [rsp]
	//ret
	shellcode.Write([]byte{0xff, 0xe0, 0x48, 0x8b, 0x04, 0x24, 0xc3})
	return shellcode.Bytes()

}
func main() {

	shellcode := modEpilogue64(0x4f, uint64(0x173d1), uint64(0x5b20))
	fmt.Print("[")
	for _, hex := range shellcode {
		fmt.Printf("0x%02x ", hex)
	}
	fmt.Println("]")

}
