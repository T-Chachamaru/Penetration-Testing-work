SQL Injection low——
没有任何防护措施,后端直接拼接的SQL语句,正常注入即可
![SQL 1](/dvwa/images/sql1.png)

SQL Injection medium——
前端做了限制,用select表单限制用户输入,但任何前端限制都是不可靠的
![SQL 2](/dvwa/images/sql2.png)
抓包修改即可注入
![SQL 3](/dvwa/images/sql3.png)

SQL Injection high——
其实没太看明白high在哪,随便闭合一下即可
![SQL 4](/dvwa/images/sql4.png)

SQL Injection(Blind) low——
测试输入可发现存在布尔盲注,找到闭合符号为单引号
![SQL 5](/dvwa/images/sql5.png)
接下来用0' or if(xxx,1,0)迭代测试即可,或者直接使用sqlmap

SQL Injection(Blind) medium——
前端限制,不用多说,抓包改就是
![SQL 6](/dvwa/images/sql6.png)

SQL Injection(Blind) high——
和普通注入一样,只不过变成了盲注,需要指定回显页面
![SQL 7](/dvwa/images/sql7.png)

Weak Session IDs low——
弱会话,通常指的是会话ID简单可控,可轻易通过会话伪造来绕过登陆验证
通过抓包可以看到,sessionID每次都只是简单地加一
![IDs 1](/dvwa/images/ids1.png)
通过伪造sessionm直接绕过了登陆验证
![IDs 2](/dvwa/images/ids2.png)

Weak Session IDs medium——
这次session使用的是时间戳作为值,但也很容易伪造
![IDs 3](/dvwa/images/ids3.png)
获取当前时间戳,作为session发送即可
![IDs 4](/dvwa/images/ids4.png)

Weak Session IDs high——
这次session使用的是md5加密,但md5已经不可靠,同时明文值也过于简单,容易被破解出来
![IDs 5](/dvwa/images/ids5.png)
![IDs 6](/dvwa/images/ids6.png)
只要根据加密成相应的md5值,作为session发送即可
![IDs 7](/dvwa/images/ids7.png)