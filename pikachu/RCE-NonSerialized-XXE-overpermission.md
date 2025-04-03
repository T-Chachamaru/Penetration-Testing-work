1.exec "ping"
有一些网页上会使用系统调用的网络测试命令,如果程序设计错误,那么可以利用这个漏洞来执行任意命令。
![RCE 1](/pikachu/images/rce1.png)

2.exec "evel"
php的evel函数将传入的字符串转换为相应的对象,并返回对象执行后相应的结果,因此也可以造成任意命令执行的漏洞。
![RCE 2](/pikachu/images/rce2.png)

3.PHP反序列化漏洞
根据类定义构造payload
![unserialize 1](/pikachu/images/php1.png)
输出后反序列化自动执行php代码
![unserialize 2](/pikachu/images/php2.png)

4.XXE漏洞
构造XXE payload
<?xml version="1.0"?>
<!DOCTYPE ANY [
     <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<a>&xxe;</a>
注入获得数据
![XXE 1](/pikachu/images/xxe1.png)

5.水平越权
登陆一个账号
![水平越权 1](/pikachu/images/水平1.png)
修改用户名参数进入到了其他用户的账号
![水平越权 2](/pikachu/images/水平2.png)

6.垂直越权
首先登陆管理员账号得到请求结构
![垂直越权 1](/pikachu/images/垂直1.png)
替换成普通用户session
![垂直越权 2](/pikachu/images/垂直2.png)
修改成功,拥有越权漏洞
![垂直越权 3](/pikachu/images/垂直3.png)