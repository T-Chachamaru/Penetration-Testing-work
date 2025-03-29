## CSRF

### 1. CSRF (GET)
- **原理**：CSRF 是基于会话的攻击，需目标用户已登录才能实施。
  ![csrf 1](/pikachu/images/csrf1.png)
- **观察**：修改信息的页面使用 GET 请求，参数为 `sex`、`phonenum`、`add`、`email`。
  ![csrf 2](/pikachu/images/csrf2.png)
- **构造攻击**：
  - URL 示例：`http://127.0.0.1/pikachu/vul/csrf/csrfget/csrf_get_edit.php/?sex=1&phonenum=1&add=1&email=1&submit=submit`，可直接修改用户信息。
  - 工具方法：使用 Burp Suite 抓包并生成 CSRF PoC。
  ![csrf 3](/pikachu/images/csrf3.png)
  ![csrf 4](/pikachu/images/csrf4.png)

### 2. CSRF (POST)
- **特点**：与 GET 不同，无法通过 URL 点击确认，需构造精心设计的 CSRF PoC。

## SSRF

### 1. SSRF (CURL)
- **特征**：URL 参数中包含明显的路径，后端使用 HTTP 请求函数（CURL）实现。
  ![ssrf 1](/pikachu/images/ssrf1.png)
- **构造攻击**：使用 `file:///C://password.txt`，通过 `file` 协议读取文件。
  ![ssrf 2](/pikachu/images/ssrf2.png)

### 2. SSRF (file_get_contents)
- **特点**：`file_get_contents` 支持 PHP 伪协议，可用于读取敏感信息。
  ![ssrf 3](/pikachu/images/ssrf3.png)
- **构造攻击**：使用 `php://filter/read=convert.base64-encode/resource=ssrf_info/info2.php`，读取文件并以 Base64 编码返回。
  ![ssrf 4](/pikachu/images/ssrf4.png)