#!/bin/env python3
def scrambler(obj):
    sb = []
    for x in range(len(obj)):
        charAt = ord(obj[x])
        if charAt < ord('a') or charAt > ord('m'):
            if charAt < ord('n') or charAt > ord('z'):
                if charAt < ord('A') or charAt > ord('M'):
                    sb.append(chr(charAt))
                    continue
            i = charAt - 13
            charAt = i
            sb.append(chr(charAt))
            continue
        i = charAt + 13
        charAt = i
        sb.append(chr(charAt))
        continue
    return ''.join(sb)


alpha = 'abcdefghijklmnopqrstuvwxyz'
scram_alpha = scrambler(alpha)

# print(alpha)
# print(scram_alpha)

lst = [97, 110, 116, 110, 103, 98, 95, 118, 102, 95, 99, 110, 118, 97]
stir = ""
for x in lst:
    stir += chr(x)
print('inctf{' + scrambler(stir) + '}')
