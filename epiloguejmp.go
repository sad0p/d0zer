package main
import(
	"fmt"
	"encoding/binary"
	"bytes"
)

func ModEpilogue64(pSize int32, pEntry uint64, oEntry uint64) []byte {
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
	*/
	var incOff uint32 = 0x12
	encPsize := make([]byte, 4)
	binary.LittleEndian.PutUint32(encPsize, uint32(pSize))
	var numZeros uint32 = 0 
	for _, b := range encPsize {
		fmt.Printf("%02x\n", b)
		if b != 0x00 {
			numZeros++
		}
	}
	incOff += (numZeros - 1)

	var shellcode bytes.Buffer;
	shellcode.Write([]byte{0xe8}) //call instruction
	
	//encode the offset
	encOff := make([]byte, 4)
	binary.LittleEndian.PutUint32(encOff, incOff)

	//write offset for call instruction
	shellcode.Write(encOff)

	//write sub rax, encPsize
	shellcode.Write([]byte{0x48, 0x83, 0xe8})
	shellcode.Write(encPsize[:numZeros])

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
/*
func main() {

	shellcode := modEpilogue64(0x4f, uint64(0x173d1), uint64(0x5b20))
	fmt.Print("[")
	for _, hex := range shellcode {
		fmt.Printf("0x%02x ", hex)
	}
	fmt.Println("]")

}
*/