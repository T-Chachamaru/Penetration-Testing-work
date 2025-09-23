#### 1. 统计与摘要 (Statistics and Summary)

`统计 (Statistics)` 菜单是进行初步分析和宏观了解网络流量的强大工具。它提供了对捕获文件的多种摘要信息，帮助分析师快速形成调查假设。

##### 常规统计 (General Statistics)

- **解析地址 (Resolved Addresses)**:
    
    - **功能**: 列出捕获文件中出现的所有 IP 地址及其通过 DNS 解析获得的主机名。
        
    - **用途**: 快速识别通信涉及的所有域名和主机，评估其是否与安全事件相关。
        
- **协议层次结构 (Protocol Hierarchy)**:
    
    - **功能**: 以树状结构展示捕获文件中所有协议的分布情况，包括数据包数量和流量百分比。
        
    - **用途**: 宏观了解网络中主要的服务和协议使用情况，快速定位异常或不常见的协议流量。
        
- **对话 (Conversations)**:
    
    - **功能**: 按二层（以太网）、三层（IPv4/IPv6）和四层（TCP/UDP）列出两个特定端点之间的所有流量会话。
        
    - **用途**: 识别通信最频繁的端点对，追踪特定主机之间的完整交互过程。
        
- **端点 (Endpoints)**:
    
    - **功能**: 与“对话”类似，但它列出的是单个唯一的端点地址，而不是成对的会话。
        
    - **用途**: 识别参与通信的所有唯一主机（MAC 地址、IP 地址等）。
        

##### 名称解析与 GeoIP (Name Resolution and GeoIP)

- **MAC 地址解析**: 在“端点”窗口中，可以通过左下角的 **“名称解析” (Name Resolution)** 按钮，将 MAC 地址的前三个字节解析为制造商名称（OUI）。
    
- **IP 与端口解析**: 默认关闭。需要在 `编辑 (Edit) -> 首选项 (Preferences) -> 名称解析 (Name Resolution)` 中启用。启用后，IP 地址会尝试解析为主机名，端口号会显示为知名服务名称（如 80 -> http）。
    
- **IP 地理位置 (GeoIP)**: 默认关闭。需要下载 MaxMind 的 GeoIP 数据库文件，并在 `名称解析` 设置中指定其路径。配置完成后，Wireshark 会在 IP 协议详情中自动显示该 IP 的地理位置信息。
    

##### 协议特定统计 (Protocol-Specific Statistics)

- **IPv4 / IPv6**: 提供针对特定 IP 版本的详细统计，包括源、目标、协议分布等。
    
- **DNS**: 分解所有 DNS 查询和响应，按查询类型（A, AAAA, MX 等）、操作码、响应码等进行统计。
    
- **HTTP**: 分解所有 HTTP 流量，统计请求（GET, POST 等）和响应码（200, 404, 500 等）。
    

#### 2. 数据包过滤原理 (Packet Filtering Principles)

Wireshark 中有两种类型的过滤器，它们用途不同，语法也不同。

|类型|**捕获过滤器 (Capture Filter)**|**显示过滤器 (Display Filter)**|
|---|---|---|
|**目的**|在捕获开始前设置，**只保存**匹配的数据包。|在捕获后应用，**只显示**匹配的数据包（隐藏其他）。|
|**时机**|捕获前|捕获后（可随时更改）|
|**复杂性**|语法相对简单，支持的协议较少。|语法极其强大，支持超过 3000 种协议的深度过滤。|
|**风险**|**风险高**：如果过滤器设置不当，可能会丢失关键证据。|**风险低**：只是隐藏数据，原始捕获文件不受影响。|

> **最佳实践**: 除非明确知道要捕获什么，否则**先捕获所有流量，再使用显示过滤器进行分析**。

- **捕获过滤器语法示例**: `tcp port 80`
    
- **显示过滤器语法示例**: `tcp.port == 80`
    

#### 3. 显示过滤器详解 (Display Filters in Detail)

这是 Wireshark 最强大的功能。

##### 比较运算符 (Comparison Operators)

|运算符|符号|含义|示例|
|---|---|---|---|
|`eq`|`==`|等于|`ip.src == 10.10.10.100`|
|`ne`|`!=`|不等于|`ip.src != 10.10.10.100`|
|`gt`|`>`|大于|`ip.ttl > 250`|
|`lt`|`<`|小于|`ip.ttl < 10`|
|`ge`|`>=`|大于或等于|`ip.ttl >= 0xFA`|
|`le`|`<=`|小于或等于|`ip.ttl <= 0xA`|

##### 逻辑表达式 (Logical Expressions)

|运算符|符号|含义|示例|
|---|---|---|---|
|`and`|`&&`|逻辑与|`(ip.src == 10.0.0.1) and (tcp.port == 443)`|
|`or`|`||`|
|`not`|`!`|逻辑非|`!(ip.src == 10.0.0.5)`|

##### 过滤器工具栏 (The Filter Toolbar)

- **自动补全**: 输入协议名称后按 `.`，会自动提示该协议下的所有可过滤字段。
    
- **语法高亮**:
    
    - **绿色**: 语法正确，过滤器有效。
        
    - **红色**: 语法错误，过滤器无效。
        
    - **黄色**: 语法可用但可能产生歧义或不可靠（例如，使用已弃用的写法）。
        

#### 4. 常用显示过滤器示例 (Common Display Filter Examples)

##### IP 过滤器 (IP Filters)

|过滤器|描述|
|---|---|
|`ip`|显示所有 IPv4 数据包。|
|`ip.addr == 10.10.10.111`|显示源或目标 IP 为 `10.10.10.111` 的所有数据包。|
|`ip.src == 10.10.10.111`|显示源 IP 为 `10.10.10.111` 的所有数据包。|
|`ip.dst == 10.10.10.111`|显示目标 IP 为 `10.10.10.111` 的所有数据包。|
|`ip.addr == 10.10.10.0/24`|显示 `10.10.10.0/24` 子网内的所有流量。|

##### TCP 与 UDP 过滤器 (TCP and UDP Filters)

|过滤器|描述|
|---|---|
|`tcp.port == 80`|显示源或目标 TCP 端口为 80 的所有数据包。|
|`udp.port == 53`|显示源或目标 UDP 端口为 53 的所有数据包。|
|`tcp.srcport == 1234`|显示源 TCP 端口为 1234 的所有数据包。|
|`tcp.dstport == 80`|显示目标 TCP 端口为 80 的所有数据包。|

##### 应用层协议过滤器 (Application Layer Protocol Filters)

|过滤器|描述|
|---|---|
|`http`|显示所有 HTTP 流量。|
|`dns`|显示所有 DNS 流量。|
|`http.response.code == 200`|显示所有 HTTP 响应码为 "200 OK" 的数据包。|
|`http.request.method == "GET"`|显示所有 HTTP GET 请求。|
|`dns.flags.response == 0`|显示所有 DNS 请求。|
|`dns.qry.type == 1`|显示所有 DNS A 记录查询。|

#### 5. 高级过滤技术 (Advanced Filtering Techniques)

|过滤器|类型|描述|示例|
|---|---|---|---|
|`contains`|比较运算符|在特定字段中搜索**区分大小写**的子字符串。|`http.server contains "Apache"`|
|`matches`|比较运算符|使用**不区分大小写**的正则表达式在字段中进行模式匹配。|`http.host matches "\.(php\|html)"`|
|`in`|集合成员|检查字段值是否存在于一个集合中。|`tcp.port in {80 443 8080}`|
|`upper()`|函数|将字段的字符串值转换为大写再进行比较。|`upper(http.server) contains "APACHE"`|
|`lower()`|函数|将字段的字符串值转换为小写再进行比较。|`lower(http.server) contains "apache"`|
|`string()`|函数|将非字符串值（如数字）转换为字符串，以便进行模式匹配。|`string(frame.number) matches "[13579]$"`|

#### 6. 提高效率：工具与配置 (Efficiency: Tools and Configuration)

##### 显示过滤器表达式构建器 (Display Filter Expression Builder)

位于 `分析 (Analyze) -> 显示过滤器表达式 (Display Filter Expression)`，这是一个内置的向导，列出了所有可用的协议和字段，可以帮助你构建复杂的过滤器而无需记住所有语法。

##### 书签和过滤按钮 (Bookmarks and Filter Buttons)

- **书签**: 你可以将常用或复杂的过滤器保存为书签，方便日后快速调用。
    
- **按钮**: 你还可以将最常用的过滤器创建为工具栏上的按钮，实现一键过滤。
    

##### 配置文件 (Profiles)

Wireshark 允许你创建多个配置文件。每个配置文件都可以有自己独立的布局、着色规则、过滤按钮和首选项设置。这对于在不同类型的调查（例如，恶意软件分析 vs. 网络性能故障排查）之间快速切换非常有用。

#### 7. 威胁狩猎：识别 Nmap 扫描 (Threat Hunting: Detecting Nmap Scans)

Nmap 是一款行业标准的网络扫描工具。作为分析师，能够从网络流量中识别出其独特的扫描模式至关重要。

##### TCP 标志过滤器参考 (TCP Flag Filter Reference)

下表总结了用于定位特定 TCP 标志组合的 Wireshark 显示过滤器：

|标志组合|描述|十进制值过滤器|标志位过滤器|
|---|---|---|---|
|**SYN**|仅设置 SYN 标志|`tcp.flags == 2`|`tcp.flags.syn == 1`|
|**ACK**|仅设置 ACK 标志|`tcp.flags == 16`|`tcp.flags.ack == 1`|
|**SYN, ACK**|同时设置 SYN 和 ACK|`tcp.flags == 18`|`(tcp.flags.syn == 1) and (tcp.flags.ack == 1)`|
|**RST**|仅设置 RST 标志|`tcp.flags == 4`|`tcp.flags.reset == 1`|
|**RST, ACK**|同时设置 RST 和 ACK|`tcp.flags == 20`|`(tcp.flags.reset == 1) and (tcp.flags.ack == 1)`|
|**FIN**|仅设置 FIN 标志|`tcp.flags == 1`|`tcp.flags.fin == 1`|

##### TCP 连接扫描 (`-sT`)

- **原理**: 依赖并**完成**完整的三次握手。
    
- **用户**: 通常由非特权（non-root）用户执行。
    
- **特征**: TCP 窗口大小通常**大于 1024** 字节。
    
- **流量模式**:
    
    - **开放端口**: `SYN` -> `SYN, ACK` -> `ACK`
        
    - **关闭端口**: `SYN` -> `RST, ACK`
        
- **检测过滤器**:
    
    ```
    tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size > 1024
    ```
    

##### SYN 扫描 (`-sS` / 半开放扫描)

- **原理**: **不完成**三次握手。发送 `SYN` 后，如果收到 `SYN, ACK` 则立即发送 `RST` 中断连接。
    
- **用户**: 需要特权（root）用户执行。
    
- **特征**: TCP 窗口大小通常**小于或等于 1024** 字节。
    
- **流量模式**:
    
    - **开放端口**: `SYN` -> `SYN, ACK` -> `RST`
        
    - **关闭端口**: `SYN` -> `RST, ACK`
        
- **检测过滤器**:
    
    ```
    tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size <= 1024
    ```
    

##### UDP 扫描 (`-sU`)

- **原理**: 无需握手。向目标 UDP 端口发送数据包。
    
- **流量模式**:
    
    - **开放端口**: 无响应。
        
    - **关闭端口**: 目标返回一个 **ICMP "目标不可达, 端口不可达"** 消息。
        
- **检测过滤器** (查找关闭端口的响应):
    
    ```
    icmp.type == 3 and icmp.code == 3
    ```
    

#### 8. 威胁狩猎：识别网络攻击 (Threat Hunting: Detecting Network Attacks)

##### ARP 欺骗与中间人攻击 (ARP Spoofing & MITM Attacks)

ARP 欺骗是一种通过发送伪造的 ARP 数据包，将攻击者的 MAC 地址与受害者的 IP 地址相关联的攻击，从而实现流量劫持（中间人攻击）。

- **ARP 协议要点**:
    
    - 仅在本地网络工作，不可路由。
        
    - 无内置身份验证机制，协议本身不安全。
        
- **分析过滤器**:
    

|目的|过滤器|
|---|---|
|**全局搜索**|`arp`|
|**ARP 请求**|`arp.opcode == 1`|
|**ARP 响应**|`arp.opcode == 2`|
|**追踪: ARP 扫描**|`arp.dst.hw_mac == 00:00:00:00:00:00`|
|**追踪: ARP 中毒**|`arp.duplicate-address-detected` or `arp.duplicate-address-frame`|

- **可疑情况**: 发现针对同一个 IP 地址存在两个来自不同 MAC 地址的 ARP 响应。Wireshark 的专家信息通常会对此类冲突发出警告。
    

#### 9. 主机与用户识别 (Host and User Identification)

在调查中，识别出与恶意活动相关的主机和用户是至关重要的一步。

##### DHCP 分析 (DHCP Analysis)

DHCP 流量，特别是客户端的请求包，包含了丰富的主机识别信息。

- **核心数据包类型**:
    
    - **Request**: `dhcp.option.dhcp == 3`
        
    - **ACK** (确认): `dhcp.option.dhcp == 5`
        
    - **NAK** (拒绝): `dhcp.option.dhcp == 6`
        
- **DHCP 请求包中的关键信息**:
    
    - **Option 12 (主机名)**: `dhcp.option.hostname contains "keyword"`
        
    - **Option 50**: 客户端请求的 IP 地址。
        
    - **Option 61**: 客户端的 MAC 地址。
        
- **DHCP ACK 包中的关键信息**:
    
    - **Option 15 (域名)**: `dhcp.option.domain_name contains "keyword"`
        

##### NetBIOS (NBNS) 分析 (NetBIOS (NBNS) Analysis)

NBNS 查询通常包含主机名信息。

- **全局搜索**: `nbns`
    
- **主机名过滤**: `nbns.name contains "keyword"`
    

##### Kerberos 分析 (Kerberos Analysis)

在域环境中，Kerberos 流量是识别用户和主机的金矿。

- **全局搜索**: `kerberos`
    
- **用户账户搜索**:
    
    - **字段**: `kerberos.CNameString` 包含用户名或主机名。
        
    - **技巧**: 主机名通常以 `$` 结尾。要只查找用户名，可以使用 `NOT` 运算符排除。
        
    - **过滤器**:
        
        ```
        # 查找包含特定关键字的用户名或主机名
        kerberos.CNameString contains "keyword"
        # 仅查找不以 $ 结尾的用户名
        kerberos.CName-String and !(kerberos.CNameString contains "$" )
        ```
        
- **其他关键信息**:
    
    - `kerberos.realm`: 域名。
        
    - `kerberos.SNameString`: 服务名称 (例如 `krbtg` 表示票据授予服务)。
        
    - `addresses`: 请求包中包含客户端 IP 地址和 NetBIOS 名称。
        

#### 10. 威胁狩猎：识别隧道流量 (Detecting Tunneled Traffic)

攻击者常利用受信任的协议（如 DNS 和 ICMP）来封装恶意流量，以绕过防火墙和 IDS/IPS。

##### ICMP 隧道分析 (ICMP Tunneling Analysis)

攻击者在 ICMP 数据包的负载 (payload) 中隐藏 C2 通信或泄露数据。

- **指标**:
    
    - 异常大量的 ICMP 流量。
        
    - 异常大的 ICMP 数据包（正常 ping 包通常为 64 字节）。
        
- **检测过滤器**:
    
    ```
    data.len > 64 and icmp
    ```
    

##### DNS 隧道分析 (DNS Tunneling Analysis)

攻击者将命令或数据编码后，作为子域名放在 DNS 查询中，发送到其控制的恶意 DNS 服务器。

- **指标**:
    
    - 异常长的 DNS 查询名称。
        
    - 大量的、针对同一主域下不同子域的 DNS 请求。
        
    - 查询名称看起来像是随机字符或 Base64 编码。
        
- **检测过滤器**:
    
    ```
    # 查找已知隧道工具的模式
    dns contains "dnscat"
    
    # 查找异常长的 DNS 查询 (并排除 mDNS 本地查询)
    dns.qry.name.len > 15 and !mdns
    ```

#### 11. 明文协议分析：FTP (Plaintext Protocol Analysis: FTP)

文件传输协议 (FTP) 因其简单性而被广泛使用，但也正因如此，它缺乏安全性。在不安全的环境中使用 FTP 会带来多种风险。

##### FTP 的安全风险 (Security Risks of FTP)

- 中间人攻击
    
- 凭证窃取和未经授权的访问
    
- 网络钓鱼
    
- 恶意软件植入
    
- 数据窃取
    

##### FTP 响应码过滤 (Filtering by FTP Response Codes)

FTP 使用三位数的响应码来传达命令的状态。分析这些响应码是快速了解 FTP 会话活动的关键。

|响应码系列|描述|示例过滤器|
|---|---|---|
|**x1x 系列**|信息请求响应（如系统、目录、文件状态）|`ftp.response.code == 211`|
|**x2x 系列**|连接消息（如服务就绪、进入被动模式）|`ftp.response.code == 227`|
|**x3x 系列**|认证消息（如登录成功、用户名有效）|`ftp.response.code == 230`|

- **登录与认证状态码**:
    

|状态码|含义|
|---|---|
|`230`|用户成功登录。|
|`231`|用户成功登出。|
|`331`|用户名有效，需要输入密码。|
|`430`|用户名或密码无效。|
|`530`|未登录，密码无效（**常见的登录失败代码**）。|

##### FTP 命令过滤 (Filtering by FTP Commands)

可以直接过滤客户端发送的命令，以追踪用户行为。

- **用户名**: `ftp.request.command == "USER"`
    
- **密码**: `ftp.request.command == "PASS"`
    
- **密码内容**: `ftp.request.arg == "password"`
    
- **列出目录**: `ftp.request.command == "LIST"`
    

##### 高级用法：检测攻击模式 (Advanced Usage: Detecting Attack Patterns)

- **暴力破解信号 (Brute-force Signal)**: 查找大量的登录失败尝试。
    
    ```
    ftp.response.code == 530
    ```
    
- **密码喷洒信号 (Password Spray Signal)**: 查找多个不同用户尝试使用同一个静态密码的记录。
    
    ```
    (ftp.request.command == "PASS" ) and (ftp.request.arg == "password")
    ```
    

#### 12. 明文协议分析：HTTP (Plaintext Protocol Analysis: HTTP)

超文本传输协议 (HTTP) 是 Web 流量的骨干。由于其明文特性，它是网络取证中信息最丰富的协议之一。

> **注意**: HTTP/2 是 HTTP 的修订版，旨在提升性能和安全性，支持二进制数据传输。在 Wireshark 中可以使用 `http2` 过滤器进行分析。

##### HTTP 请求与响应过滤 (Filtering HTTP Requests & Responses)

- **请求方法**:
    

|方法|描述|过滤器|
|---|---|---|
|`GET`|请求获取指定资源。|`http.request.method == "GET"`|
|`POST`|向服务器提交数据（如表单）。|`http.request.method == "POST"`|

- **响应状态码**:
    

|状态码|含义|过滤器|
|---|---|---|
|`200 OK`|请求成功|`http.response.code == 200`|
|`301/302`|永久/临时重定向||
|`401 Unauthorized`|需要授权|`http.response.code == 401`|
|`403 Forbidden`|禁止访问|`http.response.code == 403`|
|`404 Not Found`|未找到资源|`http.response.code == 404`|
|`500/503`|服务器内部错误/服务不可用|`http.response.code == 503`|

##### HTTP 参数过滤 (Filtering by HTTP Parameters)

- **请求参数**:
    
    - `http.user_agent`: 客户端的浏览器和操作系统信息。
        
    - `http.request.uri`: 请求的资源路径 (如 `/login.php`)。
        
    - `http.request.full_uri`: 完整的请求 URL。
        
    - `http.host`: 请求的目标主机名。
        
- **响应参数**:
    
    - `http.server`: 服务器软件名称 (如 "Apache")。
        
    - `data-text-lines`: 响应正文中的明文数据。
        

##### 专题：用户代理 (User-Agent) 分析

`User-Agent` 字段是识别恶意扫描器和非标准客户端的重要来源。

- **可疑迹象**:
    
    - 短时间内来自同一 IP 的多个不同 User-Agent。
        
    - 非标准的、自定义的或拼写错误的 User-Agent (如 "Mozlila")。
        
    - User-Agent 中包含扫描工具名称，如 `Nmap`, `Nikto`, `sqlmap`, `Wfuzz`。
        
    - User-Agent 字段中包含 Shellcode 或其他 payload 数据。
        
- **检测过滤器**:
    
    ```
    (http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap")
    ```
    

##### 专题：Log4j 漏洞利用分析

- **攻击特征**:
    
    - 攻击通常始于一个 `POST` 请求。
        
    - Payload 中包含特征字符串，如 `jndi:ldap` 或 `Exploit.class`。
        
- **检测过滤器**:
    
    ```
    http.request.method == "POST"
    (frame contains "jndi") or (frame contains "Exploit")
    ```
    

#### 13. 加密协议分析：HTTPS/TLS (Encrypted Protocol Analysis: HTTPS/TLS)

HTTPS 使用 TLS 协议对 HTTP 流量进行加密，以防范窃听和篡改。如果没有解密密钥，分析师无法直接查看传输的数据。

##### 分析加密流量（无需解密）

即使无法解密，我们仍然可以从 TLS 握手过程中获取关键信息。

- **TLS 握手**:
    
    - **客户端问候 (Client Hello)**: `tls.handshake.type == 1`
        
    - **服务器问候 (Server Hello)**: `tls.handshake.type == 2`
        
- **用途**: 通过过滤这些握手包，可以识别出哪些客户端 IP 正在与哪些服务器 IP 建立加密连接，即使无法看到具体内容。
    
- **过滤示例** (排除本地 SSDP 广播流量):
    
    ```
    # 查找客户端问候
    (http.request or tls.handshake.type == 1) and !(ssdp)
    ```
    

##### 解密 TLS 流量 (Decrypting TLS Traffic)

如果能获取到 TLS 会话密钥，就可以在 Wireshark 中解密 HTTPS 流量。

- **`SSLKEYLOGFILE` 方法**:
    
    1. **原理**: 现代浏览器（如 Chrome 和 Firefox）支持将 TLS 会话密钥导出到一个日志文件中。
        
    2. **配置**:
        
        - 在操作系统中设置一个名为 `SSLKEYLOGFILE` 的环境变量，其值为一个文件的绝对路径 (例如 `C:\Users\YourUser\ssl_keys.log`)。
            
        - 重启浏览器。之后，该浏览器发起的所有 TLS 连接的会话密钥都会被追加到这个文件中。
            
    3. **加载密钥**: 在 Wireshark 中，进入 `编辑 (Edit) -> 首选项 (Preferences) -> 协议 (Protocols) -> TLS`，在 `(Pre)-Master-Secret log filename` 字段中指定你创建的密钥日志文件路径。
        

##### 解密后的数据视图 (Post-Decryption Data Views)

成功加载密钥后，Wireshark 会自动解密匹配的 TLS 流量。在数据包详情面板的底部，你会看到新的标签页，可以查看解密后的数据：

- `Decrypted TLS`
    
- `Decompressed Header`
    
- `Reassembled TCP / Reassembled SSL`
    
- 解密后的 **HTTP** 或 **HTTP/2** 流量。