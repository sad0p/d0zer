        global _start

        section .text

_start:
	push rdi
	push rsi
	push rdx 
	jmp message

message: 
	call shellcode
	db "hello -- this is a non destructive payload", 0xa

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

	call get_eip
	sub rax, 0x4f ; size of virus code
	sub rax, 0x173d1 ; textSegment.virtualAddr + textSegment.FileSZ AKA end of textSegment original code and start of vxcode, rax is now the base virtual addr
	add rax, 0x5b20 ; OEP
	jmp rax



get_eip:
	mov rax, [rsp]
	ret




