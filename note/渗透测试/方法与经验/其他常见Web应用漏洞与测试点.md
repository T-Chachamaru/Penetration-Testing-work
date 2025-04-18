#### 概述
除了 SQL 注入、XSS、CSRF 等主流漏洞外，Web 应用还可能存在其他多种类型的安全风险。这些漏洞可能涉及配置错误、逻辑缺陷、信息泄露、第三方组件漏洞等。全面的渗透测试需要关注这些潜在的攻击面。

#### 常见漏洞与测试点

1.  **暴力猜解用户名及密码 (Brute Force)**
    *   **测试点**：登录接口、管理后台、API 认证等。
    *   **方法**：尝试常见弱口令组合（如 `admin:admin`, `test:test`, `root:password`）和基于目标信息的字典（结合用户名枚举）。
    *   **工具**：Burp Suite Intruder, Hydra, Medusa等。

2.  **敏感目录与文件扫描 (Sensitive Directory/File Scanning)**
    *   **测试点**：Web 服务器根目录及子目录。
    *   **目标**：备份文件 (`.bak`, `.zip`, `.rar`, `.tar.gz`, `~`, `.swp`)、配置文件 (`web.config`, `.htaccess`, `database.yml`)、源码泄露 (`.git`, `.svn`, `.DS_Store`)、临时文件、测试页面、未授权访问的管理后台、编辑器上传目录、日志文件等。
    *   **方法**：使用目录扫描工具配合字典进行探测。
    *   **工具**：DirSearch, Gobuster, ffuf, 御剑后台扫描, 7kbscan, 破壳 Web 扫描器等。

3.  **PhpMyAdmin 万能密码**
    *   **测试点**：暴露在公网的 PhpMyAdmin 登录接口。
    *   **方法**：在用户名处尝试输入特定字符串（如 `localhost'@'@`、`' or ''='` 等，具体取决于版本和配置）可能绕过认证。
    *   **注意**：此为特定旧版本漏洞，现代版本通常已修复。

4.  **反射型 XSS (Reflected XSS in Unexpected Places)**
    *   **测试点**：除了常规输入点，错误页面、图片加载失败路径、甚至某些响应头都可能将用户输入未经过滤地反射回来。
    *   **方法**：在 URL 参数、路径、甚至文件名后添加特殊字符或 XSS Payload，观察响应内容。

5.  **隐藏域/源码中的敏感信息泄露 (Sensitive Information in Hidden Fields/Source Code)**
    *   **测试点**：HTML 源码、JavaScript 文件、CSS 文件、HTTP 响应头、注释。
    *   **目标**：明文密码、API 密钥、内部 IP、开发注释、敏感路径、业务逻辑信息。
    *   **方法**：仔细审查浏览器开发者工具中的源码、网络请求和响应。

6.  **逻辑漏洞 - 任意用户密码重置 (Logical Flaw - Arbitrary Password Reset)**
    *   **测试点**：密码找回/重置流程。
    *   **方法**：（详见逻辑漏洞部分）通过修改用户标识符（ID, username, email, phone）、绕过验证步骤或利用 Token 缺陷来重置非本人账户的密码。

7.  **短信/邮件炸弹 (SMS/Email Bombing)**
    *   **测试点**：发送短信验证码、邮件验证码、邮件订阅、用户注册激活等接口。
    *   **方法**：利用接口缺乏频率限制，通过工具（如 Burp Intruder）大量重复发送请求，对目标手机号或邮箱造成轰炸。

8.  **版本控制系统源码泄露 (VCS Source Code Disclosure)**
    *   **测试点**：Web 根目录或相关目录下是否存在 `.git`, `.svn`, `.hg`, `.bzr` 等版本控制系统目录。
    *   **方法**：尝试访问 `/.git/config`, `/.svn/entries` 等特征文件。如果存在，可使用工具下载泄露的源码。
    *   **工具**：GitHack, dvcs-ripper, SVN Gopher, Seay SVN Exploiter。

9.  **内网共享扫描 (Internal Network Share Scanning)**
    *   **测试点**：当测试环境处于目标内网时。
    *   **方法**：使用工具扫描局域网内开放的 SMB/NFS 共享，查找可能存在的敏感文件或可写目录。访问方式：`\\<IP>\sharename`。

10. **HTTP 响应拆分 (HTTP Response Splitting)**
    *   **测试点**：应用程序将用户输入未经过滤地插入到 HTTP 响应头中（如 `Location` 重定向头、`Set-Cookie` 头）。
    *   **方法**：通过注入回车换行符 (`%0d%0a`) 来插入额外的响应头或响应体，可能导致缓存投毒、XSS、会话固定等。

11. **端口扫描 (Port Scanning)**
    *   **测试点**：目标服务器 IP。
    *   **目标**：发现除 Web 服务（80/443）外其他开放的端口及对应服务（如 SSH(22), FTP(21), RDP(3389), DB(3306/1433/1521), 管理端口等），寻找其他攻击入口。
    *   **工具**：Nmap, Masscan, 尖刀端口扫描。

12. **目录遍历/路径穿越 (Directory Traversal / Path Traversal)**
    *   **测试点**：需要访问文件或目录的参数（如 `file=`, `path=`, `include=`）。
    *   **方法**：使用 `../` 或其编码形式 (`%2e%2e/`, `..%2f`) 尝试访问文件系统中的任意文件（如 `/etc/passwd`, `C:\Windows\win.ini`）。

13. **越权访问页面 (Unauthorized Access to Privileged Pages)**
    *   **测试点**：管理后台、用户中心、需要特定权限才能访问的功能页面。
    *   **方法**：（详见逻辑漏洞部分）尝试以低权限用户身份直接访问高权限 URL。

14. **IIS 短文件名泄露 (IIS Short Filename Disclosure)**
    *   **测试点**：运行旧版本 IIS 的 Windows 服务器。
    *   **原理**：利用 Windows 8.3 文件名格式（如 `PROGRA~1`）的特性，通过发送带有 `~1` 的请求，可以猜测或枚举服务器上存在的文件和目录名（特别是前 6 个字符）。
    *   **方法**：使用专用工具（如 IIS Shortname Scanner）或手动构造请求（如 `GET /config~1.aspx HTTP/1.1`）进行探测。
    *   **危害**：泄露敏感文件名（如备份文件、配置文件），为后续攻击提供信息。

15. **老旧库/框架漏洞 (Vulnerable Libraries/Frameworks)**
    *   **测试点**：应用使用的前端库（如 jQuery）、后端框架（如 Struts2, ThinkPHP）、CMS（如 WordPress, Drupal）、中间件（如 WebLogic, JBoss）。
    *   **方法**：
        *   通过指纹识别（Wappalyzer, WhatWeb）确定库/框架及其版本。
        *   在 CVE 数据库 (Mitre, NVD)、Exploit-DB 等平台搜索该版本是否存在已知漏洞。
        *   **示例**：jQuery < 1.7 存在 DOM XSS 风险（利用 `location.hash`）。

16. **目录浏览 (Directory Listing)**
    *   **测试点**：Web 服务器配置。
    *   **原理**：服务器配置允许列出目录内容，当访问一个没有默认索引文件（如 `index.html`）的目录时，会显示该目录下的文件和子目录列表。
    *   **危害**：可能泄露敏感文件、源码结构、备份文件等。
    *   **验证**：直接访问已知或猜测的目录（如 `/images/`, `/js/`, `/uploads/`），看是否返回文件列表。

17. **URL 跳转/开放重定向 (URL Redirection / Open Redirect)**
    *   **测试点**：实现页面跳转功能的参数（如 `url=`, `redirect=`, `next=`）。
    *   **原理**：应用程序接收用户提供的 URL 并进行重定向，但未对 URL 进行充分验证，允许跳转到任意外部恶意网站。
    *   **危害**：主要用于钓鱼攻击，诱导用户点击看似合法的链接，最终跳转到恶意站点。
    *   **验证**：修改跳转参数的值为外部恶意域名，看是否成功跳转。

18. **点击劫持/UI 覆盖 (Clickjacking / UI Redress Attack)**
    *   **测试点**：未使用 `X-Frame-Options` 或 `Content-Security-Policy: frame-ancestors` 响应头的页面。
    *   **原理**：攻击者创建一个恶意页面，使用 `<iframe>` 嵌入目标网站页面，并通过 CSS 定位将目标页面上的敏感操作按钮（如“确认付款”、“删除账户”）透明地覆盖在恶意页面的诱导性按钮（如“领取奖品”）之下，欺骗用户点击。
    *   **验证**：检查响应头，或尝试在本地 HTML 文件中用 `iframe` 嵌入目标页面。

19. **未加密登录请求 (Unencrypted Login Request)**
    *   **测试点**：登录页面。
    *   **原理**：登录表单通过 HTTP 而非 HTTPS 提交，导致用户名和密码在网络中明文传输。
    *   **危害**：容易被中间人攻击者嗅探窃取凭证。
    *   **验证**：使用浏览器开发者工具或抓包工具查看登录请求是否通过 HTTP 发送。

20. **HTTP TRACE/TRACK 方法启用 (HTTP TRACE/TRACK Method Enabled)**
    *   **测试点**：Web 服务器配置。
    *   **原理**：`TRACE` 和 `TRACK` 方法设计用于调试，会回显客户端发送的完整请求。如果启用，攻击者可以利用此方法（通常结合 XSS）窃取用户的 Cookie（尤其是设置了 `HttpOnly` 属性的 Cookie，因为 `TRACE` 请求由浏览器发出，可以访问到）。
    *   **验证**：发送 `TRACE / HTTP/1.1` 请求，或使用 Burp Scanner 等工具检测。

21. **DNS 域传送漏洞 (DNS Zone Transfer Vulnerability - AXFR)**
    *   **测试点**：目标域名的权威 DNS 服务器配置。
    *   **原理**：DNS 服务器配置不当，允许任意客户端请求完整的域区域文件（Zone File），导致该域下所有的 DNS 记录（包括子域名、IP 地址、MX 记录等）泄露。
    *   **验证**：使用 `dig` (`dig axfr @ns_server domain.com`) 或 `nslookup` (`nslookup`, `server ns_server`, `ls -d domain.com`) 命令尝试进行域传送。

22. **私有 IP 地址泄露 (Private IP Address Disclosure)**
    *   **测试点**：HTTP 响应体（HTML 源码、注释、JS 代码）、响应头（如 `Server`, `X-Via` 等）。
    *   **原理**：应用程序或服务器配置错误，导致内部私有 IP 地址（如 `192.168.x.x`, `10.x.x.x`, `172.16.x.x-172.31.x.x`）出现在对外部用户的响应中。
    *   **危害**：泄露内部网络结构信息。

23. **物理路径信息泄露 (Physical Path Disclosure)**
    *   **测试点**：错误页面、调试信息、注释、配置文件。
    *   **原理**：应用程序在报错或输出调试信息时，包含了服务器文件系统的绝对路径。
    *   **危害**：泄露服务器目录结构，可能有助于文件包含、文件上传等攻击。

24. **应用重装漏洞 (Application Reinstallation Vulnerability)**
    *   **测试点**：查找应用安装脚本或路径。
    *   **原理**：某些 Web 应用安装完成后，未删除或限制对安装脚本（如 `install.php`, `setup.php`）的访问。攻击者访问这些脚本可能重新初始化应用，导致数据丢失或被覆盖，甚至可能在过程中设置管理员密码。
    *   **验证**：尝试访问常见的安装脚本路径。

25. **任意文件下载/读取 (Arbitrary File Download/Read)**
    *   **测试点**：提供文件下载功能的接口或参数。
    *   **原理**：下载功能未对用户提供的文件名或路径进行充分验证和限制，允许用户通过构造特殊路径（如目录遍历 `../`）或文件名下载服务器上的任意文件。
    *   **危害**：泄露源码、配置文件、敏感数据等。