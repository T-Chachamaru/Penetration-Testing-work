XSS(DOM) low——
DOM型XSS,类似于反射XSS,但代码不与后端交互,而是通过前端JS注入达到攻击的效果
可以看到JS逻辑是把构造select表单输出到页面中,其中第一个输出从default参数中获取但没有任何过滤
![XSS(DOM) 1](/dvwa/images/xss1.png)
因此可以使用default参数注入
![XSS(DOM) 2](/dvwa/images/xss2.png)

XSS(DOM) medium——
与上相同,注意闭合select标签即可

XSS(DOM) high——
后端进行了白名单限制,进行双参数或注释绕过
![XSS(DOM) 3](/dvwa/images/xss3.png)

XSS(Reflected) low——
正常注入
![XSS(Reflected) 1](/dvwa/images/xss4.png)

XSS(Reflected) medium——
双写绕过
![XSS(Reflected) 2](/dvwa/images/xss5.png)

XSS(Reflected) high——
事件触发绕过
![XSS(Reflected) 3](/dvwa/images/xss6.png)

XSS(Stored) low——
存储型XSS,直接注入payload
![XSS(Stored) 1](/dvwa/images/xss7.png)

XSS(Stored) medium——
过滤了script,使用<img src=x onerror=alert('XSS')>
![XSS(Stored) 2](/dvwa/images/xss8.png)

XSS(Stored) high——
对script的过滤更加严格,但依然可以<img src=x onerror=alert('XSS')>
![XSS(Stored) 3](/dvwa/images/xss9.png)