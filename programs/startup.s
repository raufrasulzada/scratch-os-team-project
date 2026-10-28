.syntax unified
.cpu cortex-m3
.thumb

.section .text.startup, "ax", %progbits

.global _start
.type _start, %function
.thumb_func

_start:
    bl main
    bl sys_exit

1:
    b 1b

.size _start, . - _start
