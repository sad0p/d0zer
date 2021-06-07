    global _start
    section .text

_start:
    jmp message

message:
    call shellcode
    db "hello -- this is a non-destructive payload", 0xa

shellcode:
    pop ecx
    mov ebx, 1
    mov edx, 0x2a
    mov eax, 4
    int 0x80

    ;mov eax, 1
    ;mov ebx, 0
    ;int 0x80