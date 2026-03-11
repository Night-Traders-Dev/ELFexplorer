.section .rodata
msg:
    .ascii "Hello, World from AArch64 ASM!\n"
len = . - msg

.section .text
.globl _start
.type _start, %function
_start:
    mov x0, #1          // fd = stdout
    adr x1, msg
    mov x2, #len
    mov x8, #64         // sys_write
    svc #0

    mov x0, #0
    mov x8, #93         // sys_exit
    svc #0
