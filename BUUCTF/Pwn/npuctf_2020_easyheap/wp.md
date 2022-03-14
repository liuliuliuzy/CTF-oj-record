libc2.27

off-by-one

首先弄清楚libc2.26下tcache与off-by-one的利用方式，然后学习libc2.27

## tcache bin

### 2.26

- 64bit下一共有64个bin，每个bin最多存放7个chunk，单链表结构，并且和fastbin一样都是LIFO，在单链表头部操作。
- 不同于fastbin的是，单链表中的指针指向的是用户空间开始的地址，并非整个chunk开始的地址
- 每个bin对应一种大小的chunk，0x10/0x20/0x30/.../0x400，一共64个
- free的时候先放入对应大小的tcache bin中

### 2.27

- `tcache_entry`结构体发生改变，增加了`struct tcache_perthread_struct *key`变量，用于检查double free
- 相应的放入和取出的函数`tcache_put()`和`tcache_get()`也都增加了对于`key`指针的操作。
- 更多细节见[https://www.anquanke.com/post/id/219292](https://www.anquanke.com/post/id/219292)
- 
