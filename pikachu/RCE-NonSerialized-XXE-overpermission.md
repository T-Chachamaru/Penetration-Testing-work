1.exec "ping"
有一些网页上会使用系统调用的网络测试命令,如果程序设计错误,那么可以利用这个漏洞来执行任意命令。
![RCE 1](/pikachu/images/rce1.png)

2.exec "evel"
php的evel函数将传入的字符串转换为相应的对象,并返回对象执行后相应的结果,因此也可以造成任意命令执行的漏洞。
![RCE 2](/pikachu/images/rce2.png)