Brute Force low——
bp抓包,发送到重发器。通常管理员用户的账号是admin、root、administrator等账号,因此我们可以用这些账号进行爆破
![Brute 1](/dvwa/images/Brute1.png)
设置变量,配置字典,使用集群炸弹模式进行爆破
![Brute 2](/dvwa/images/Brute2.png)
获得密码
![Brute 3](/dvwa/images/Brute3.png)

Brute Force medium——
bp抓包,进行输入测试,除了登陆失败后要等几秒没有发现更多的验证条件
![Brute 4](/dvwa/images/Brute4.png)
如上使用重发器进行爆破
![Brute 5](/dvwa/images/Brute5.png)

Brute Force high——
继续进行输入测试,查看验证条件,能够发现除了依然会停止几秒,token值也有变化,因此可以使用递归搜索的方式进行爆破
![Brute 6](/dvwa/images/Brute6.png)
设置递归搜索
![Brute 7](/dvwa/images/Brute7.png)
![Brute 8](/dvwa/images/Brute8.png)

Command Injection low——
显示输入ip地址,那么可以尝试使用管道符进行注入
![Command 1](/dvwa/images/Command1.png)
![Command 2](/dvwa/images/Command2.png)

Command Injection medium——
依然能够使用管道符进行注入,源代码只禁止了;和&&符号
![Command 3](/dvwa/images/Command3.png)

Command Injection high——
过滤了大部分符号,但源代码贴心地给管道符多加了一个空格,让管道符的过滤因此失效。
![Command 4](/dvwa/images/Command4.png)