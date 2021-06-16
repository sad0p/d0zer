# d0zer
Elf binary infector written in Golang. It can be used for infecting executables of type ET_DYN and ET_EXEC with a payload of your creation. Utilizing the classic elf text segment padding algorithm by Silvio Cesar, your payload (parasite) will run before native functionality of the binary effectively backooring the binary.

d0zer currently allows for up to a page size payload (4096 bytes). It is capable of infecting both x86_32 and x86_64  elf executable binaries executables.

# Motivation
My motivations are quite simple, I have a proclovity for the darkside of computer science (lol) and binary infections of a target requires a decent amount of overhead knowledge and skill prequisite to accomplish it (TO ME), so I set out to learn from papers, books and specs from the past (see references), throwed Golang in the middle for increased difficulty and here I am.

# Usage

<pre>
[sad0p@Arch-Deliberate d0zer]$ ./d0zer --help
Usage of ./d0zer:
  -debug
    	see debug out put (generated payload, modifications, etc)
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
    	path to binary targetted for infection
[sad0p@Arch-Deliberate d0zer]$ 
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

