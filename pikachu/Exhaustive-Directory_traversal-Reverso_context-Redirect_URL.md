## 暴力破解与安全漏洞

### 1. 基于表单的暴力破解
- **方法**：
  - 使用 Burp Suite 抓包，进入 Intruder 模式。
  - 设置“集群炸弹”（Cluster Bomb）模式，加载字典进行爆破。
  ![image1](/pikachu/images/image1.png)
- **结果**：过滤响应内容后，获取正确的密码。

### 2. 验证码绕过（Server 端）
- **分析**：
  - 查看验证码生成逻辑：无论输入什么，提交后页面刷新并更新验证码。
  - 推测后端逻辑：每次提交返回新页面，包含新验证码，验证码具有有效期。
- **验证**：
  - 抓包观察，发现验证码未随页面刷新更新。
  ![image2](/pikachu/images/image2.png)
- **攻击**：
  - 使用字典攻击，过滤响应后得到正确账号和密码。
  ![image3](/pikachu/images/image3.png)

### 3. 验证码绕过（Client 端）
- **发现**：测试发现验证码限制仅在前端实现。
- **方法**：
  - 直接抓包，绕过前端限制进行爆破。
  ![image4](/pikachu/images/image4.png)
- **结果**：获取正确的账号和密码。
  ![image5](/pikachu/images/image5.png)

### 4. Token 防爆破
- **步骤**：
  1. 从响应包中提取 Token。
  2. 将 Token 复制到递归提取的请求包 Payload 中。
     ![image6](/pikachu/images/image6.png)
  3. 将资源池改为单线程模式，使用字典攻击。
     ![image7](/pikachu/images/image7.png)
- **结果**：爆破成功。

### 5. 目录遍历
- **发现**：随意点击，发现存在传参点。
  ![image8](/pikachu/images/image8.png)
- **攻击**：进行目录遍历，访问未授权文件。
  ![image9](/pikachu/images/image9.png)

### 6. 敏感信息泄露
- **问题**：无需登录即可直接访问 `abc.php`。
  ![image10](/pikachu/images/image10.png)

### 7. 不安全的 URL 重定向
- **分析**：URL 参数由前端传递至后端，存在可控点。
- **攻击**：构造不安全的 URL 重定向。
  ![image11](/pikachu/images/image11.png)
  ![image12](/pikachu/images/image12.png)