        global _start

        section .text

_start:
	push rdi
	push rsi
	push rdx 
	jmp message
shellcode:
	mov rax, 0x1 		;write system call
	mov rdi, 0x1      	;stdout fd

	pop rsi			;make rsi a ptr to message
	mov rdx, 0x2a 		;message length
	syscall			

	;xor rdi, rdi		; 0 return status
	;xor rax, rax
	;mov al, 0x3c		; syscall for exit
	;syscall 
	pop rdx
	pop rsi
	pop rdi
	mov rax,  0x0000000000005b20
	jmp rax

message: 
	call shellcode
	db "hello -- this is a non destructive payload", 0xa
