## 概述 (Overview)

HTTP 请求走私 (HTTP Request Smuggling) 是一种攻击技术，当处理 HTTP 请求链中的不同网络基础设施组件（如代理服务器、负载均衡器、Web 服务器）对请求边界的解释不一致时产生。攻击者可以构造一个模糊的 HTTP 请求，使得链中的一个组件（如前端代理）认为这是一个完整的请求，而另一个组件（如后端服务器）则将其解析为两个或多个独立的请求。这可能导致第二个（“走私的”）请求被错误地附加到下一个合法用户的请求之前，从而引发各种安全问题，如会话劫持、缓存投毒、绕过安全控制等。

## 利用条件 (Conditions for Exploitation)

*   **存在请求处理链 (Request Processing Chain):** 通常涉及至少一个前端服务器（如反向代理、负载均衡器）和一个或多个后端服务器。
*   **头部解析差异 (Header Parsing Discrepancies):** 前端和后端服务器对 `Content-Length` (CL) 和 `Transfer-Encoding` (TE) 这两个用于确定请求体结束位置的 HTTP 头部有不同的处理优先级或解释方式。
*   **持久连接/HTTP管道 (Persistent Connections/HTTP Pipelining):** 允许在同一个 TCP 连接上发送多个 HTTP 请求。这是请求走私能够将一个请求的部分“注入”到后续请求的前提。
*   **可控的请求构造 (Controllable Request Construction):** 攻击者能够发送精心构造的、包含特定 `Content-Length` 和/或 `Transfer-Encoding` 头部组合的 HTTP 请求。
*   **对CRLF的精确控制 (`\r\n`):** `Content-Length` 和分块编码的大小计算会受到回车符 (`\r`) 和换行符 (`\n`) 的影响，攻击者需要精确控制它们。

## 相关概念与组件 (Related Concepts & Components)

### HTTP 请求结构 (HTTP Request Structure)

每个 HTTP 请求主要包含请求行、请求头部和请求正文。

1.  **请求行 (Request Line):** 请求的第一行，包含方法 (如 `POST`)、请求 URL 路径 (如 `/admin/login`) 和 HTTP 版本 (如 `HTTP/1.1`)。
2.  **请求头部 (Request Headers):** 包含请求的元数据，如 `Host`, `Content-Type`, `Content-Length`, `Transfer-Encoding` 等。
3.  **请求正文 (Request Body):** 实际数据内容，如表单数据、JSON 负载、文件上传等。GET 请求通常没有正文。

### 关键头部 (Key Headers)

1.  **`Content-Length` 头部 (Content-Length Header):**
    *   **作用:** 以字节为单位指示请求或响应正文的大小。
    *   **示例:**
        ```
        POST /submit HTTP/1.1
        Host: good.com
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 14

        q=smuggledData
        ```
    *   **注意:** 如果 `Content-Length` 值与实际正文大小不符，可能导致请求被截断或处理不完整。

2.  **`Transfer-Encoding` 头部 (Transfer-Encoding Header):**
    *   **作用:** 指定消息体的编码形式，最常见的是 `chunked`（分块传输）。
    *   **`chunked` 编码:** 消息体被分成一系列块，每个块前有其大小（十六进制），以大小为 `0` 的块结束。
    *   **示例:**
        ```
        POST /submit HTTP/1.1
        Host: good.com
        Content-Type: application/x-www-form-urlencoded
        Transfer-Encoding: chunked

        b
        q=smuggledData
        0
        ```
        (这里的 `b` 是十六进制，表示11字节，即 `q=smuggledData` 的长度，不含换行符。实际应用中，块大小后紧跟一个CRLF，数据块后也紧跟一个CRLF。)
    *   **其他值:** `compress`, `deflate`, `gzip` (较少用于请求走私场景的TE利用)。

### 现代网络应用组件 (Modern Network Application Components)

1.  **前端服务器 (Frontend Server):** 通常是反向代理或负载均衡器，接收外部请求并转发到后端。
2.  **后端服务器 (Backend Server):** 处理用户请求，与数据库交互，执行业务逻辑。
3.  **数据库 (Database):** 存储应用数据。
4.  **API (Application Programming Interfaces):** 用于前后端通信或与其他服务集成。
5.  **微服务 (Microservices):** 将大型应用拆分为小型、独立的服务。

### 负载均衡器与反向代理 (Load Balancers & Reverse Proxies)

1.  **负载均衡器 (Load Balancer):** 将传入流量分配到多个服务器，确保高可用性和可靠性。例如 AWS ELB, HAProxy, F5 BIG-IP。
2.  **反向代理 (Reverse Proxy):** 位于 Web 服务器前，接收客户端请求并转发给后端服务器，可提供负载均衡、缓存、SSL终止等功能。例如 NGINX, Apache `mod_proxy`, Varnish。

### 缓存机制的作用 (Role of Caching Mechanisms)

缓存用于存储和重用之前获取或计算的数据，以加速后续请求。在请求走私中，缓存投毒 (Cache Poisoning) 是一种常见的攻击后果，攻击者可以将恶意内容走私到缓存中，随后所有请求该资源的用户都会收到恶意内容。

## HTTP 请求走私原理 (HTTP Request Smuggling Origin)

请求走私的核心在于前端和后端服务器对 HTTP 请求边界（即请求何时结束）的解释存在差异。

*   **歧义来源:** 当一个请求同时包含 `Content-Length` 和 `Transfer-Encoding: chunked` 头部时，RFC 规范规定 `Transfer-Encoding` 优先。但并非所有服务器实现都严格遵守。
*   **优先级差异:**
    *   一些服务器组件优先使用 `Content-Length`。
    *   另一些则优先使用 `Transfer-Encoding`。
*   **利用方式:** 攻击者利用这种差异，构造一个请求，使得前端服务器根据一个头部确定请求结束，而后端服务器根据另一个头部确定请求结束，导致部分数据被“遗留”下来，并被后端服务器错误地附加到下一个请求的开头。

## 主要走私技术 (Main Smuggling Techniques)

### CL.TE: 前端认 CL，后端认 TE (Frontend uses Content-Length, Backend uses Transfer-Encoding)

*   **原理:**
    *   前端服务器（如代理）使用 `Content-Length` 头部来确定请求体的长度。
    *   后端服务器优先使用 `Transfer-Encoding: chunked` 头部。
*   **利用方法:** 攻击者发送一个同时包含 `Content-Length` 和 `Transfer-Encoding: chunked` 的请求。
    *   `Content-Length` 的值被设置得足够大，以包含整个“走私的”请求。
    *   `Transfer-Encoding: chunked` 头部指示分块传输，并在“主”请求体之后用一个大小为 `0` 的块来标记分块数据的结束。
    *   前端服务器根据 `Content-Length` 读取所有数据并转发。
    *   后端服务器看到 `Transfer-Encoding: chunked`，它会处理到 `0` 块为止作为第一个请求，`0` 块之后剩余的数据（即走私的请求）会被保留在缓冲区中，等待下一个进入该TCP连接的请求，并附加在其前面。
*   **示例 Payload:**
    ```
    POST /search HTTP/1.1
    Host: example.com
    Content-Length: 130 # 前端认为请求体有130字节
    Transfer-Encoding: chunked

    0 # 后端遇到这个0，认为第一个请求的chunked body结束

    POST /update HTTP/1.1 # 这部分是走私的请求
    Host: example.com
    Content-Length: 13 # 或者适当的长度
    Content-Type: application/x-www-form-urlencoded

    isadmin=true
    ```
    **注意:** 示例中的 `Content-Length: 130` 需要精确计算从 `0\r\n\r\nPOST /update...` 到 `isadmin=true` 的实际字节数。 `0` 后面必须有 `\r\n\r\n`。 走私请求 `POST /update...` 之前也需要 `\r\n`。

### TE.CL: 前端认 TE，后端认 CL (Frontend uses Transfer-Encoding, Backend uses Content-Length)

*   **原理:**
    *   前端服务器优先使用 `Transfer-Encoding: chunked` 头部。
    *   后端服务器优先（或仅）使用 `Content-Length` 头部。
*   **利用方法:** 攻击者发送一个同时包含 `Content-Length` 和 `Transfer-Encoding: chunked` 的请求。
    *   `Transfer-Encoding: chunked` 用于让前端服务器处理整个（包括走私部分的）分块消息。
    *   第一个分块的大小（十六进制）被设置为包含“主”请求数据加上走私请求的部分或全部。
    *   `Content-Length` 的值被设置得较小，只覆盖“主”请求的初始部分。
    *   前端服务器根据分块编码处理整个请求直到最后的 `0` 块。
    *   后端服务器忽略 `Transfer-Encoding`，根据 `Content-Length` 读取请求体。它只读取 `Content-Length` 指定的字节数作为第一个请求，剩余的数据（即走私的请求）则被保留并附加到下一个请求。
*   **示例 Payload:**
    ```
    POST / HTTP/1.1
    Host: example.com
    Content-Length: 4 # 后端认为请求体只有4字节 (例如 "78\r\n")
    Transfer-Encoding: chunked

    78 # 十六进制，表示120字节。这个块包含下面的走私请求
    POST /update HTTP/1.1
    Host: example.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 15 # 走私请求自身的Content-Length

    isadmin=true
    0 # 分块结束
    ```
    **注意:** `Content-Length: 4` 意味着后端只读取 `78\r\n` 这4个字节作为第一个请求体。`78` 之后的数据 (`POST /update...isadmin=true\r\n`) 会被前端作为第一个分块的内容发送给后端，但后端因为 CL 的限制只读取了开头。当这个分块数据被完全发送后，`isadmin=true` 之后到 `0` 之前的部分，会被后端视为下一个请求的开始。更经典的 TE.CL 是让 `Content-Length` 只覆盖第一个分块声明 (如 `78\r\n`)，这样其后的数据 `POST /update ...` 会成为被走私的部分。

### TE.TE: 前后端均认 TE，利用混淆 (Both use Transfer-Encoding, exploiting obfuscation)

*   **原理:** 前端和后端服务器都声称支持 `Transfer-Encoding`，但它们可能对畸形或多个 `Transfer-Encoding` 头部的处理方式不同。攻击者通过构造一个让其中一个服务器忽略（或错误处理）`Transfer-Encoding` 头部，使其回退到使用 `Content-Length` (从而变成 CL.TE 或 TE.CL)，或者对分块的解析产生差异。
*   **利用方法:**
    *   发送多个 `Transfer-Encoding` 头部，其中一个可能是畸形的。
    *   例如，一个服务器可能处理第一个 `Transfer-Encoding: chunked`，而另一个服务器可能因为第二个畸形的 `Transfer-Encoding: chunked1` 而产生混乱，或选择性忽略。
*   **示例 Payload:**
    ```
    POST / HTTP/1.1
    Host: example.com
    Content-length: 4 # 后备的CL，如果一个服务器忽略TE
    Transfer-Encoding: chunked
    Transfer-Encoding: chunked1 # 可能是畸形的或导致一个服务器忽略TE

    4e # 假设一个服务器按这个分块处理 (78字节)
    POST /update HTTP/1.1
    Host: example.com
    Content-length: 15 # 走私请求的CL

    isadmin=true
    0
    ```
    *   **场景1 (导致CL.TE):** 前端忽略所有TE头（由于第二个TE头无效），使用 `Content-Length: 4`。后端处理第一个 `Transfer-Encoding: chunked`。
    *   **场景2 (导致TE.CL):** 前端处理第一个 `Transfer-Encoding: chunked`。后端忽略所有TE头，使用 `Content-Length: 4`。
    *   **场景3 (TE解析差异):** 两个服务器都处理 `Transfer-Encoding`，但对畸形头部的处理方式导致它们对实际块的边界有不同理解。

## 演示 (Demonstration - 基于原文THM示例)

以下步骤概述了在 `httprequestsmuggling.thm` 靶场环境中利用 CL.TE 漏洞的过程。

1.  **基准请求:** 使用 Burp Suite 代理拦截一个发往网站的正常 `POST` 请求（例如，提交表单）。
2.  **构造Payload (CL.TE):** 将请求发送到 Burp Intruder，并修改为如下结构：
    ```
    POST / HTTP/1.1
    Host: httprequestsmuggling.thm
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 160 # 前端读取160字节 (需要精确计算)
    Transfer-Encoding: chunked

    0 # 后端认为第一个请求在此结束

    # 被走私的请求 (目标是contact.php)
    POST /contact.php HTTP/1.1
    Host: httprequestsmuggling.thm
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 500 # 一个足够大的值，或者精确计算

    username=test&query=§PAYLOAD§
    ```
    *   `Content-Length: 160`: 前端代理会读取从 `0\r\n\r\nPOST /contact.php...` 开始的160字节。
    *   `Transfer-Encoding: chunked` 和随后的 `0`: 后端服务器会在此处结束第一个请求。
    *   `POST /contact.php ...`: 这是被走私的请求。`§PAYLOAD§` 是 Intruder 的 payload 标记。
3.  **Intruder 配置:**
    *   **Payload Type:** Null payloads.
    *   **Payload Settings:** 生成大量（如10000个）空 payload。这是为了持续发送请求，希望能夹带其他用户的请求。
    *   **Resource Pool:** 创建新资源池，设置线程数（如10个），延迟（如2000ms）和随机变化。
4.  **发起攻击:** 点击 "Start attack"。
5.  **检查结果:**
    *   几分钟后，访问 `/submissions` 目录（假设提交的查询保存在此）。
    *   如果攻击成功，`contact.php` 的请求（由攻击者走私）可能会捕获到其他正常用户提交到 `/` (主POST请求) 的数据，这些数据会被附加到 `query=` 参数的末尾。
    *   遍历 `/submissions` 中的文本文件，查找被附加到 `query` 参数中的敏感信息（如密码）。
    *   **注意:** 在走私生效期间，如果攻击者自己访问易受攻击的应用程序，可能会捕获到自己的请求，而不是目标用户的。

## 注意事项 (Important Notes)

*   **工具行为:** 一些测试工具（如 Burp Repeater）可能会自动“修复”或调整 `Content-Length` 头部，这可能干扰手动测试。需要注意工具的默认行为。
*   **测试风险:** HTTP 请求走私测试可能对目标网站造成破坏（如缓存投毒、影响其他用户请求、甚至导致后端服务中断）。在生产环境测试时务必极其小心，并获得授权。
*   **WAF/IPS:** Web 应用防火墙 (WAF) 或入侵防御系统 (IPS) 可能会检测并阻止已知的请求走私特征。

## 防御策略 (Defense Strategies)

1.  **统一头部处理 (Consistent Header Handling):** 确保请求链中的所有服务器（代理、负载均衡器、后端服务器）对 `Content-Length` 和 `Transfer-Encoding` 头部的解释和优先级处理方式完全一致。理想情况下，严格遵守 RFC 规范（TE优先于CL）。
2.  **HTTP/2 优先 (Prefer HTTP/2):** 尽可能让前端服务器与后端服务器之间使用 HTTP/2 通信。HTTP/2 使用不同的请求/响应复用机制，不易受此类基于文本头部解析差异的攻击。
3.  **禁用持久连接/管道 (Disable Persistent Connections/Pipelining):** 如果业务允许，可以考虑禁用代理和后端服务器之间的持久连接或HTTP管道，但这通常会带来性能损失。
4.  **请求规范化 (Request Normalization):** 前端服务器可以对传入的请求进行规范化处理，例如：
    *   如果同时存在 `Content-Length` 和 `Transfer-Encoding`，则删除其中一个（通常是 `Content-Length`）或拒绝该请求。
    *   确保 `Transfer-Encoding` 的值是合法的。
5.  **日志监控与审计 (Logging, Monitoring & Auditing):** 监控服务器流量，寻找异常的请求模式或指示请求走私的迹象。定期审计服务器配置。
6.  **WAF/RASP:** 使用配置良好的 Web 应用防火墙 (WAF) 或运行时应用自我保护 (RASP) 技术，它们可能包含针对请求走私的检测规则。
7.  **团队意识与培训 (Team Awareness & Training):** 确保开发和运维团队了解 HTTP 请求走私的风险和预防措施。
8.  **后端验证 (Backend Validation):** 后端服务器不应盲目信任前端传递过来的所有信息，应有自身的安全校验。

[[HTTP2请求走私]]
[[WebSocket请求走私]]
[[浏览器不同步]]