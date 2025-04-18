File Inclusion low——
文件包含漏洞,本地文件包含可以读取网站配置文件从而获得某些敏感信息。而远程包含漏洞则可以包含远程文件来getshell
首先在远程服务器上创建webshell
![File Inclusion 1](/dvwa/images/Inclusion1.png)
修改url包含远程webshell并执行命令
![File Inclusion 2](/dvwa/images/Inclusion2.png)

File Inclusion medium——
设置了str_replace函数过滤一些字符,但str_replace函数只对字符串过滤一次,因此可以双写绕过
![File Inclusion 3](/dvwa/images/Inclusion3.png)

File Inclusion high——
使用fnmatch指定特定开头的文件名,可以使用php的内置协议来读取任意文件
![File Inclusion 4](/dvwa/images/Inclusion4.png)

File Upload low——
文件上传漏洞,可以毫无阻碍地上传webshell.php
![File Upload 1](/dvwa/images/upload1.png)

File Upload medium——
通过Content-Type字段判断文件类型,如果不是png或者jpeg则失败,那么修改MIME绕过
![File Upload 2](/dvwa/images/upload2.png)

File Upload high——
取后缀名限制png、jpeg,用getimagesize判断是否是图片,这样就只能上传图片马,然后用文件包含漏洞读取木马
![File Upload 3](/dvwa/images/upload3.png)
![File Upload 4](/dvwa/images/upload4.png)

Insecure CAPTCHA——
不安全的认证,后端使用的认证判断依托前端的简单参数传递,攻击者可以修改参数,控制变量绕过认证