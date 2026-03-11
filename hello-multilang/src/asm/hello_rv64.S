.section .rodata
msg:
    .ascii "Hello, World from RISC-V RV64 ASM!\n"
len = . - msg

.section .text
.globl _start
.type _start, @function
_start:
    li a0, 1            # fd = stdout
    la a1, msg
    li a2, len
    li a7, 64           # sys_write
    ecall

    li a0, 0
    li a7, 93           # sys_exit
    ecall
