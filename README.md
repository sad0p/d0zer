# d0zer
Elf binary infector written in Golang. It can be used for infecting executables of type ET_DYN and ET_EXEC with a payload of your creation. Utilizing the classic elf text segment padding algorithm by Silvio Cesar, your payload (parasite) will run before native functionality of the binary.

d0zer currently allows for up to a page size payload (4096 bytes). It is capable of infecting both x86_32 and x86_64  elf executable binaries executables.

