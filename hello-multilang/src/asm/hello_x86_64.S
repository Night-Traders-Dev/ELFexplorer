.intel_syntax noprefix
.section .rodata
msg:
    .ascii "Hello, World from x86_64 ASM!\n"
len = . - msg

.section .text
.globl _start
.type _start, @function
_start:
    mov rax, 1          # sys_write
    mov rdi, 1          # fd = stdout
    lea rsi, msg[rip]
    mov rdx, len
    syscall

    mov rax, 60         # sys_exit
    xor rdi, rdi
    syscall
