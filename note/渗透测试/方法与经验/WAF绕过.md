#### 概述
WAF (Web Application Firewall) 是一种位于 Web 应用程序和客户端之间的安全屏障，旨在通过监控、过滤和阻止恶意的 HTTP/S 流量来保护 Web 应用免受攻击（如 SQL 注入、XSS、文件包含等）。WAF 通过实施一系列安全策略和规则集来识别和拦截已知或可疑的攻击模式。

#### WAF 类型
1.  **软件 WAF (Software WAF)**：以软件形式安装在被保护的服务器（主机侧）上。
    *   示例：安全狗、ModSecurity (常作为 Web 服务器模块)。
2.  **硬件 WAF (Hardware WAF)**：作为独立的物理设备部署在网络链路中（通常在服务器前端），处理流经它的所有 Web 流量。
3.  **云 WAF (Cloud WAF)**：基于云的服务，通常通过修改域名的 DNS 解析将流量引导至 WAF 服务提供商的节点进行清洗，然后再将合法流量转发回源站服务器。

#### WAF 绕过思路
WAF 绕过的核心思想是构造 WAF 规则无法识别或错误识别的恶意请求，使其看起来像是正常的业务请求，从而穿透 WAF 到达后端应用并执行攻击。或者，找到不经过 WAF 防护的途径直接访问后端应用。

#### 绕过方法

##### 1. 认证与源站绕过
*   **伪造可信来源**：
    *   **伪造搜索引擎 User-Agent**：部分旧版或配置不当的 WAF 可能信任已知的搜索引擎爬虫（如 Googlebot, Baiduspider），修改请求头中的 `User-Agent` 可能绕过检测。
    *   **访问白名单路径**：如果 WAF 配置了某些目录（如 `/admin/`）为白名单，尝试将攻击载荷置于这些路径下（如果应用逻辑允许）。
*   **直接访问源站 IP**：
    *   **场景**：主要针对**云 WAF**。如果能找到服务器的真实 IP 地址，就可以直接向该 IP 发送请求，绕过云 WAF 的流量清洗节点。
    *   **寻找源站 IP 方法**：（参考“CDN识别与绕过”部分）
        *   查找未接入 WAF 的子域名（如邮件服务 `mail.domain.com`、测试环境 `dev.domain.com`）。
        *   利用泛域名解析的配置错误，Ping 一个不存在的子域名。
        *   查询历史 DNS 解析记录。
        *   利用 SSL 证书信息。
        *   利用 Fofa、Shodan 等网络空间搜索引擎。
    *   **伪造本地访问**：修改请求头（如 `X-Forwarded-For`, `X-Real-IP`）为 `127.0.0.1` 或其他内网地址，尝试欺骗 WAF 或应用认为请求来自内部可信网络（成功率较低，依赖具体配置）。

##### 2. 协议与编码层绕过
*   **修改请求方法**：
    *   **GET -> POST/Cookie**：WAF 对 GET 请求参数的检测通常最严格。尝试将攻击载荷放入 POST 请求体、Cookie、或甚至其他 HTTP 头（如 `Referer`, `User-Agent`）中，这些地方的检测规则可能较宽松或未启用。
*   **参数污染 (Parameter Pollution)**：
    *   提交多个同名参数，WAF 可能只检测第一个或最后一个，而后端应用处理逻辑可能不同（如 PHP 可能取最后一个，ASP 可能将所有值合并）。
    *   示例：`?id=1&id=union&id=select...` 后端可能只解析最后一个 `id` 或拼接。
*   **编码绕过**：
    *   **URL 编码**：使用 `%XX` 形式编码特殊字符（如 `%20` 代替空格，`%27` 代替单引号）。可多次编码。虽然基础，但有时仍有效或作为组合手段。
    *   **其他编码**：尝试 Unicode 编码 (`%uXXXX`)、HTML 实体编码 (`&#XX;`)、Hex 编码等，取决于 WAF 和后端应用的解析能力。
*   **HTTP 分块传输 (Chunked Encoding)**：
    *   在请求头中加入 `Transfer-Encoding: chunked`。
    *   将请求体（尤其是 POST 数据中的 Payload）分割成多个小块发送，每个块前有一个十六进制长度指示符。
    *   可能干扰 WAF 对完整 Payload 的模式匹配。
    *   示例（示意）：
        ```http
        POST /vuln.php HTTP/1.1
        Host: example.com
        Transfer-Encoding: chunked
        Content-Type: application/x-www-form-urlencoded

        4          <-- 长度
        id=1       <-- 数据块
        6          <-- 长度
         union     <-- 数据块 (注意空格可能包含在内)
        7          <-- 长度
         select    <-- 数据块
        ...        ...
        0          <-- 结束块
        \r\n
        ```

##### 3. 规则与关键字绕过
*   **大小写混合**：将关键字（如 `SELECT`, `UNION`, `FROM`）大小写混用（如 `SeLeCt`, `uNiOn`），绕过只匹配特定大小写的规则。
*   **替换空格**：使用 WAF 未拦截的字符或注释替代空格。
    *   MySQL: `/**/`, `%0a` (换行符), `%09` (Tab), `+`, `()` (函数与括号间), `.`
    *   MSSQL: `%01`-`%0f`
    *   通用: URL 编码 `%20`
*   **特殊字符/注释**：
    *   **MySQL 内联注释**：`/*! ... */` 或 `/*!50000 ... */` (仅当 MySQL 版本 >= 5.00.00 时执行)。
    *   **普通注释**：`-- -` (注意 `--` 后有空格或换行), `#` (URL 编码为 `%23`), `/**/`。
    *   **特殊符号混淆**：在关键字前后或中间加入 WAF 规则未考虑的特殊符号（如 `select~1`, `select+1`, `select/1`，效果取决于 WAF 和后端）。
    *   **拼接**：利用某些数据库（如 MSSQL）的字符串拼接符 `+` 将敏感函数名拆分（如 `'xp'+'_cmdshell'`）。
*   **关键字拆分/替换**：
    *   **双写关键字**：`UNIunionON`，如果 WAF 只是简单删除 `union`，过滤后会还原。
    *   **等价函数/操作符**：使用功能相同但名称不同的函数或操作符（如 `concat_ws()` 代替 `concat()`, `LIKE` 代替 `=`, `&&` 代替 `AND`, `||` 代替 `OR`）。
    *   **利用 WAF 自身规则**：如果发现 WAF 会将特定字符（如 `*`）替换为空，可以插入这些字符来构造 Payload（如 `sel*ect`）。
*   **其他技巧**：
    *   **括号**：在 SQL 函数名和括号之间可以插入空格或注释，如 `version/**/()`。数据或函数周围可嵌套括号 `()`。
    *   **Null 字节**：`%00` 可能用于截断字符串，影响 WAF 判断或后端处理。

##### 4. 文件上传绕过
*   **文件名/路径操纵**：
    *   **后缀名大小写**：`file.pHP`, `file.AspX`。
    *   **特殊/点/空格结尾**：`file.asp.`，`file.asp ` (Windows特性，保存时末尾的点和空格会被移除)。`file.asp::$DATA` (NTFS 流)。
    *   **添加 Null 字节**：`file.asp%00.jpg` (依赖后端处理逻辑)。
    *   **文件名前缀/特殊字符**：添加 `[0x09]` (Tab)，或在文件名前后加空格。
*   **Content-Disposition 操纵**：
    *   **修改/删除引号**：`filename=shell.asp` 代替 `filename="shell.asp"`。
    *   **添加额外空格**：`form-data; name="file"; filename="shell.asp"` 中添加空格。
    *   **参数污染**：提供多个 `filename` 参数，利用 WAF 和后端处理差异。
    *   **修改 form-data**：`f+orm-data`, `form-data; name="file" filename="shell.asp"` (注意分号后空格)，在 `form-data` 前后加 `+` 或空格。
    *   **删除 form-data**：尝试完全去掉 `form-data;` 部分（依赖后端容错性）。
    *   **filename 换行**：在 `filename="shell.asp"` 中的不同位置插入回车换行符 (`%0d%0a`)。
*   **Content-Type 操纵**：
    *   **错误/伪造 MIME 类型**：将 `Content-Type` 修改为合法的图片类型（如 `image/jpeg`）但上传脚本文件。
    *   **删除 Content-Type**。
*   **请求结构修改**：
    *   **调换参数顺序**：改变 `Content-Disposition` 和 `Content-Type` 在请求体中的顺序。
    *   **双文件上传**：在一个请求中包含两个文件的 `Content-Disposition` 定义，利用 WAF 和后端解析差异（如 IIS6 可能取第一个，安全狗可能取最后一个）。

#### WAF 绕过工具
1.  **SQLMap Tamper Scripts**：SQLMap 内置了大量用于修改注入 Payload 以绕过 WAF 的脚本 (`--tamper` 参数)。例如 `tamper=space2comment`, `tamper=versionedmorekeywords`。
2.  **Burp Suite 插件**：
    *   **Bypass WAF**：提供多种 WAF 绕过 Payload 和检测功能。
    *   **注意**：安装插件后，通常需要在 Burp Suite 的 `Project options` -> `Sessions` -> `Session Handling Rules` 中配置，使其能够自动修改请求。

#### 注意事项
*   **GET vs POST/Cookie**：通常 WAF 对 GET 参数的防护最严密，优先尝试将 Payload 移至 POST Body 或 Cookie。
*   **组合使用**：单一绕过技巧可能失效，常常需要结合多种方法（如编码+注释+大小写）。
*   **目标特定**：WAF 绕过技巧高度依赖于目标 WAF 的产品、版本和具体配置规则。需要不断测试和调整。
*   **动态性**：WAF 规则会不断更新，昨天有效的绕过方法今天可能就失效了，这是一个持续对抗的过程。