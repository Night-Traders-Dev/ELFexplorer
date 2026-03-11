.intel_syntax noprefix
.section .rodata
msg:
    .ascii "Hello, World from x86 ASM!\n"
len = . - msg

.section .text
.globl _start
.type _start, @function
_start:
    mov eax, 4          # sys_write
    mov ebx, 1          # fd = stdout
    mov ecx, msg
    mov edx, len
    int 0x80

    mov eax, 1          # sys_exit
    xor ebx, ebx
    int 0x80
