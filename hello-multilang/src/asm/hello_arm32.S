.syntax unified
.cpu cortex-a9
.section .rodata
msg:
    .ascii "Hello, World from ARM32 ASM!\n"
len = . - msg

.section .text
.globl _start
.type _start, %function
_start:
    mov r0, #1          @ fd = stdout
    ldr r1, =msg
    ldr r2, =len
    mov r7, #4          @ sys_write
    svc #0

    mov r0, #0
    mov r7, #1          @ sys_exit
    svc #0
