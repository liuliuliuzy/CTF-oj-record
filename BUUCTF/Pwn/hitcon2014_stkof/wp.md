~~反汇编都看不懂，爬了爬了...~~

调试碰到了这种问题：

```bash
./stkof: No such file or directory.
Attaching to process 916
Could not attach to process.  If your uid matches the uid of the target
process, check the setting of /proc/sys/kernel/yama/ptrace_scope, or try
again as the root user.  For more details, see /etc/sysctl.d/10-ptrace.conf
warning: process 916 is a zombie - the process has already terminated
ptrace: Operation not permitted.
/mnt/c/Windows/916: No such file or directory.
```

奇怪的是，我在`process()`加上指定libc的语句就无法调试。

如果写成光秃秃的`p = process('./stkof')`就可以，真是奇怪欸。

破案了，是加载的libc版本不对，所以实际上程序在启动之后就因为错误而结束运行了。

> process 916 is a zombie - the process has already terminated

但是之后又有了新的问题：

```
bins: This command only works with libc debug symbols.
They can probably be installed via the package manager of your choice.
See also: https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html

E.g. on Ubuntu/Debian you might need to do the following steps (for 64-bit and 32-bit binaries):
sudo apt-get install libc6-dbg
sudo dpkg --add-architecture i386
sudo apt-get install libc-dbg:i386
```

加载不了debug符号？为什么我之前指定别的libc库时好像没碰到过这问题？

-------------分界线---------------

经过一番折腾终于弄懂了一些东西，限于篇幅，这里就不写什么内容了。关于这题的解法与我个人的理解，以及我是如何解决上述问题的，都会记录在博客里。