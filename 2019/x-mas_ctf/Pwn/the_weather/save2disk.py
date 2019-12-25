import pwn
import base64
pwn.context.arch = 'amd64'

host, port = 'challs.xmas.htsp.ro', 12002

conn = pwn.remote(host, port)
conn.recvuntil("Content: b'")
encoded_bin = conn.recvuntil('\n\n\n').decode('utf-8').strip('\n').strip("'")
print(encoded_bin)
binary = base64.decodebytes(encoded_bin.encode())

file = open('binary','wb')
file.write(binary)
file.close()
