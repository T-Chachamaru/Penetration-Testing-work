## XSS（跨站脚本攻击）

### 1. 反射型 XSS (GET)
- **测试**：输入代码字符，检查输出是否被转义。
  ![XSS 1](/pikachu/images/xss1.png)
- **发现**：完全未过滤。
- **构造**：根据页面结构，输入 `</p><script>alert(123)</script>`。
  ![XSS 2](/pikachu/images/xss2.png)
- **结果**：反射成功。

### 2. 反射型 XSS (POST)
- **测试**：登录后输入代码字符，检查输出是否被转义。
  ![XSS 3](/pikachu/images/xss3.png)
- **发现**：无过滤。
- **构造**：根据页面结构，输入 `</p><script>alert(document.cookie)</script><p>`。
  ![XSS 4](/pikachu/images/xss4.png)
- **结果**：反射成功。

### 3. 存储型 XSS
- **测试**：检查是否存在过滤或转义。
  ![XSS 5](/pikachu/images/xss5.png)
- **发现**：输入 `<p>123</p>` 未被转义。
- **构造**：输入 `</p><script>alert('Hello World')</script><p>`。
  ![XSS 6](/pikachu/images/xss6.png)
- **结果**：恶意代码被存储到数据库。

### 4. DOM 型 XSS
- **测试**：随意输入，观察输入被放入 `href` 属性。
  ![XSS 7](/pikachu/images/xss7.png)
- **构造**：输入 `' onclick=alert('123')>`。
  ![XSS 8](/pikachu/images/xss8.png)
- **结果**：反射成功。
- **注意**：需尝试多种闭合方式，找到正确构造形式。

### 5. DOM 型 XSS-X
- **测试**：与之前类似，但表现稍有不同。
  ![XSS 9](/pikachu/images/xss9.png)
- **构造**：输入 `' onclick=alert('123')>`。
  ![XSS 10](/pikachu/images/xss10.png)
- **结果**：反射成功。

### 6. XSS 盲打
- **特点**：前端无回显，需多次尝试闭合构造。
  ![ cartão 11](/pikachu/images/xss11.png)
- **猜测**：`input-text` 返回可能为 `<p>` 类型元素。
- **构造**：输入 `</p><script>alert('hello')</script><p>`。
  ![XSS 12](/pikachu/images/xss12.png)
- **结果**：反射成功。

### 7. XSS 过滤
- **测试**：观察过滤规则。
  ![XSS 13](/pikachu/images/xss13.png)
- **发现**：过滤了 `<script>`。
- **构造**：
  - 方案 1：`</p><a onclick="alert('123')">你好</a><p>`。
  - 方案 2：大小写绕过 `<Script>alert('123')</Script>`。
  ![XSS 14](/pikachu/images/xss14.png)
- **结果**：反射成功。

### 8. XSS 之 htmlspecialchars
- **特点**：`htmlspecialchars` 过滤 `&`、`"`、`'`、`<`、`>`，但默认不过滤 `"` 和 `'`。
- **测试**：观察输出，发现位于元素属性中。
  ![XSS 15](/pikachu/images/xss15.png)
- **构造**：输入 `' onclick='alert("123")`。
  ![XSS 16](/pikachu/images/xss16.png)
- **结果**：反射成功。

### 9. XSS 之 href 输出
- **测试**：观察输出位置。
  ![XSS 17](/pikachu/images/xss17.png)
- **发现**：`href` 属性支持 JS 伪协议。
- **构造**：输入 `javascript:alert('123')`。
  ![XSS 18](/pikachu/images/xss18.png)
- **结果**：反射成功。

### 10. XSS 之 JS 输出
- **测试**：观察输出，发现由 JS 代码生成。
  ![XSS 19](/pikachu/images/xss19.png)
- **构造**：为避免报错，闭合标签，输入 `1111'</script><script>alert('123')</script><script>`。
  ![XSS 20](/pikachu/images/xss20.png)
  ![XSS 21](/pikachu/images/xss21.png)
- **结果**：反射成功。