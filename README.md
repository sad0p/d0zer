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