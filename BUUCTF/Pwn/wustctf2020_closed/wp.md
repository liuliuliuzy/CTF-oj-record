这什么题啊，不是栈也不是堆？

```assembly
.text:000000000040072E                 push    rbp
.text:000000000040072F                 mov     rbp, rsp
.text:0000000000400732                 mov     edi, offset aHahahaWhatElse ; "HaHaHa!\nWhat else can you do???"
.text:0000000000400737                 call    _puts
.text:000000000040073C                 mov     edi, 1          ; fd
.text:0000000000400741                 call    _close
.text:0000000000400746                 mov     edi, 2          ; fd
.text:000000000040074B                 call    _close
.text:0000000000400750                 mov     eax, 0
.text:0000000000400755                 call    shell
.text:000000000040075A                 nop
.text:000000000040075B                 pop     rbp
.text:000000000040075C                 retn
```

懂了，程序关闭stdout、stderr后进入shell，所以我们得想办法在不通过stdout和stderr的情况下拿到flag。

```sh
$exec 1>&0
$cat flag
$flag{97014b24-dcc8-400f-9a20-0f6ecdfab4a0}
```

- [linux exec与重定向](http://xstarcd.github.io/wiki/shell/exec_redirect.html)

是不是还可以反弹shell啊...没试过