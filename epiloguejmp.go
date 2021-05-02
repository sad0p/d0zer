package main
import(
	"fmt"
	"encoding/binary"
)

const (
	X64_P_SIZE_OFF    int = 8
	X64_P_ENTRY_OFF   int = 11
	x64_STUB_CALL_OFF int = 1
	X64_O_ENTRY_OFF   int = 16
)

func modEpilogue64(pSize int32, pEntry uint64, oEntry uint64)  {
	epilogue := []byte{
		0xe8, 0x12, 0x00, 0x00, 0x00, 		//call   401061 <get_eip>
		0x48, 0x83, 0xe8, 0x4f, 			//sub    $0x4f,%rax
		0x48, 0x2d, 0xd1, 0x73, 0x01, 0x00, //sub    $0x173d1,%rax
		0x48, 0x05, 0x20, 0x5b, 0x00, 0x00, //add    $0x5b20,%rax
		0xff, 0xe0, 						//jmp    *%rax
											//0000000000401061 <get_eip>:
		0x48, 0x8b, 0x04, 0x24, 			//mov    (%rsp),%rax
		0xc3, 								//ret
	}

	encpSize := make([]byte, 4)   //
	var noZeros int //does not count bytes of value 0x00 associated with extension
	if ! (pSize <= 0xff) {
		binary.BigEndian.PutUint32(encpSize, uint32(pSize))
		fmt.Printf("%2x\n", encpSize)
		for _, b := range encpSize {
			fmt.Printf("%02x\n", b)
			if b != 0x00 {
				noZeros++
			}
		}
	}
	fmt.Printf("pSize = %d | pEntry = %d | oEntry = %d\n", pSize, pEntry, oEntry)
	fmt.Println("Num of zeros in pSize ", noZeros)
	fmt.Println(epilogue)
	for i := 0; i < 4; i++ {
		fmt.Printf("%02x\n", encpSize[i])
	}

	fmt.Printf("0x%x\n", encpSize[noZeros:])
	return

}
func main() {
	modEpilogue64(355, uint64(0), uint64(0))
}
