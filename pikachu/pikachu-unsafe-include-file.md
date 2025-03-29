## 文件相关漏洞

### 1. 不安全的文件下载 (Unsafe File Download)
- **发现**：点击头像，发现关键参数 `?filename=`。
  ![file1](/pikachu/images/file1.png)
- **利用**：利用参数漏洞，下载成功。
  ![file2](/pikachu/images/file2.png)

### 2. 客户端检查 (Client Check)
- **分析**：查看前端 `<input>` 元素，发现限制由 JS 代码实现。
  ![file3](/pikachu/images/file3.png)
- **绕过**：禁用 JS，上传文件成功。
  ![file4](/pikachu/images/file4.png)

### 3. MIME 类型检查 (MIME Type)
- **观察**：检查前端 `<input>` 元素，未发现限制。
  ![file5](/pikachu/images/file5.png)
- **绕过**：抓包修改 Content-Type 为 `image/png`，上传成功。
  ![file6](/pikachu/images/file6.png)

### 4. getimagesize() 检查
- **特点**：`getimagesize()` 函数检查文件属性是否为图片。
- **方法**：制作图片马（Picture WebShell）。
  ![file7](/pikachu/images/file7.png)
- **结果**：上传成功。
  ![file8](/pikachu/images/file8.png)

### 5. 文件包含 - 本地 (File Inclusion - Local)
- **发现**：随意测试，发现后端传参点。
  ![file9](/pikachu/images/file9.png)
- **利用**：
  1. 尝试日志漏洞，观察是否能读取文件内容。
     ![file10](/pikachu/images/file10.png)
  2. 读取成功后，尝试写入 PHP 语句（注意 URL 编码），判断是否可执行任意代码。
     ![file11](/pikachu/images/file11.png)
- **结果**：执行成功。

### 6. 文件包含 - 远程 (File Inclusion - Remote)
- **发现**：随意测试，发现后端传参点。
  ![file12](/pikachu/images/file12.png)
- **利用**：使用 `http://` 协议，包含远程服务器上的 PHP 代码。
  ![file13](/pikachu/images/file13.png)
- **结果**：执行成功。