checksec
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```


IDA
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[80]; // [esp+2Ch] [ebp-5Ch] BYREF
  unsigned int v5; // [esp+7Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  be_nice_to_people();
  memset(buf, 0, sizeof(buf));
  read(0, buf, 0x50u);
  printf(buf);
  printf("%d!\n", x);
  if ( x == 4 )
  {
    puts("running sh...");
    system("/bin/sh");
  }
  return 0;
}
```

感觉是格式化字符串然后改写x？

格式化字符串的关键在于，调用printf时，输入的format str离Printf的栈有多远的距离，也就是确定格式化字符串的相对偏移

```
          ....
low -----------------

    -----------------stack of printf()
    ----------------- 
           addr
    -----------------



addr-----------------
      format string
high-----------------
          ....
```

`flag{a88625e2-888a-4afc-bd9d-eb06ad497380}`