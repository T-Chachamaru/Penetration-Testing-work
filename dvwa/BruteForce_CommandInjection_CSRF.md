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

CSRF low——
csrf是建立在会话上的攻击,该攻击可以在受害者毫不知情的情况下以受害者的名义伪造请求发送给受攻击站点,从而在未授权的情况下执行在权限保护之下的操作
通过测试,能发现修改密码的请求参数暴露在uri里
![CSRF 1](/dvwa/images/csrf1.png)
因此如果我们了解参数结构,在一个用户处于会话中时,用某种方式使用户点击由我们构造的链接,接下来就可以把用户的密码修改成我们想要的密码,就像这样。
![CSRF 2](/dvwa/images/csrf2.png)

CSRF medium——
可以看到源代码中使用stripos检查host和referer的值,如果referer中的值和host中的值匹配,则会允许操作。
![CSRF 3](/dvwa/images/csrf3.png)
因此可以构造一个html页面,这个页面的名字是host的值,点击超链接便会向修改密码的页面发送请求
![CSRF 4](/dvwa/images/csrf4.png)
![CSRF 5](/dvwa/images/csrf5.png)

CSRF high——
这里添加了checkToken函数验证token值,用户每次访问修改密码的页面便会返回到一个随机的token,只有同时提交了这个随机token才有可能访问成功。要利用此漏洞只能用存储型XSS之类的攻击获取用户的即时token,才能成功发起攻击