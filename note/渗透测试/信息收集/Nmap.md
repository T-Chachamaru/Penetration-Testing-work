## 概述 (Overview)

Nmap ("Network Mapper") 是一款开源且功能强大的网络扫描工具，广泛用于网络发现和安全审计。它利用原始 IP 报文来发现网络上的主机、探测这些主机开放的端口、确定端口上运行的服务及其版本、推测目标操作系统，并可通过 Nmap 脚本引擎 (NSE) 执行更广泛的安全相关任务。

## 识别特征 / 使用场景 (Identification / Use Cases)

Nmap 是网络安全专业人员和系统管理员的核心工具，主要用于：

1.  **网络资产发现:** 识别网络中存活的主机 (Host Discovery)。
2.  **端口扫描:** 枚举目标主机上开放的 TCP 和 UDP 端口 (Port Scanning)。
3.  **服务识别与版本探测:** 确定开放端口上运行的应用程序名称和版本号 (`-sV`)。
4.  **操作系统探测:** 根据 TCP/IP 协议栈指纹猜测远程主机的操作系统 (`-O`)。
5.  **漏洞扫描:** 利用 Nmap 脚本引擎 (NSE) 检测已知的漏洞 (`--script vuln`)。
6.  **安全审计:** 评估网络的安全状况，检查防火墙规则等。
7.  **网络映射:** 绘制网络拓扑结构。
8.  **CTF 竞赛/渗透测试:** 在信息收集阶段获取目标关键信息。

## 工作原理 (Working Principle)

Nmap 的扫描过程通常分阶段进行：

1.  **目标解析 (Target Expansion):** 解析用户输入的目标规范（如 IP 地址、域名、CIDR、列表文件）。
2.  **主机发现 (Host Discovery / Ping Scan):** (除非使用 `-Pn`) Nmap 首先判断目标主机是否在线，以避免在离线主机上浪费时间。它使用多种技术，如 ICMP echo (`-PE`), TCP SYN (`-PS`), TCP ACK (`-PA`), UDP (`-PU`) 探测，以及 ARP 请求 (`-PR`, 仅限本地网络)。
3.  **反向 DNS 解析 (Reverse DNS):** (除非使用 `-n`) Nmap 尝试查询目标 IP 地址对应的域名。
4.  **端口扫描 (Port Scanning):** 对确认在线的主机探测指定范围的端口状态（开放 `open`、关闭 `closed`、过滤 `filtered`）。常用技术包括 TCP SYN 扫描 (`-sS`, 默认且推荐)、TCP Connect 扫描 (`-sT`), UDP 扫描 (`-sU`), 以及多种隐蔽扫描 (`-sN/sF/sX`)。
5.  **服务与版本探测 (Service/Version Detection):** (如果指定 `-sV`) Nmap 向开放端口发送一系列探测报文，分析响应以确定运行的服务及其版本。
6.  **操作系统探测 (OS Detection):** (如果指定 `-O`) Nmap 分析目标对特定 TCP/IP 探测报文的响应特征（如 TCP ISN 采样、窗口大小等）来猜测操作系统。
7.  **脚本扫描 (Script Scanning):** (如果指定 `-sC` 或 `--script`) Nmap 执行选定的 NSE 脚本，进行更深入的探测、漏洞检查、信息收集或暴力破解等。
8.  **路由跟踪 (Traceroute):** (如果指定 `--traceroute`) Nmap 追踪到目标主机的网络路径。
9.  **结果输出 (Output):** 将扫描结果格式化并呈现给用户或保存到文件。

## 利用步骤 / 常用命令 (Exploitation Steps / Common Commands)

使用 Nmap 进行扫描通常包括定义目标、选择扫描类型和选项、执行扫描、分析结果。

**基本语法 (Basic Syntax):**

```bash
nmap [扫描类型...] [选项...] {目标说明}
```

**1. 目标指定 (Target Specification):**

*   **单个 IP/域名:** `192.168.1.1`, `example.thm`
*   **范围:** `192.168.1.10-20`, `192.168.1-3.1-254`
*   **CIDR:** `192.168.1.0/24`
*   **列表文件:** `-iL targets.txt` (每行一个目标)
*   **排除目标:** `--exclude 192.168.1.5`, `--excludeFile exclude.txt`

**2. 主机发现 (Host Discovery):** (决定是否扫描端口的前提)

*   `-sn`: Ping 扫描 (旧称 `-sP`)。仅进行主机发现，不扫描端口。适用于快速确定网络中有哪些主机在线。
*   `-Pn`: **重要** - 跳过主机发现阶段，假设所有目标主机在线。当目标阻止 ICMP 或常用探测端口时**必须**使用，否则 Nmap 可能将存活主机标记为 down 而不进行端口扫描。
*   `-PS <portlist>`: 对指定 TCP 端口发送 SYN 包进行发现 (默认 80)。
*   `-PA <portlist>`: 对指定 TCP 端口发送 ACK 包进行发现 (默认 80)。
*   `-PU <portlist>`: 对指定 UDP 端口发送探测包进行发现 (默认 40125)。
*   `-PE`: 使用 ICMP Echo 请求 (Ping)。
*   `-PP`: 使用 ICMP Timestamp 请求。
*   `-PM`: 使用 ICMP Address Mask 请求。
*   `-PR`: ARP 扫描 (仅限本地以太网)。默认在扫描局域网时使用，速度快。
*   `-sL`: 列表扫描。仅列出目标 IP，并尝试反向 DNS 解析，不发送任何探测包到目标。用于检查目标范围和获取域名信息。

**3. 主要扫描技术 (Scan Techniques):**

*   `-sS`: TCP SYN 扫描 (半开放扫描)。默认需要 root 权限。速度快，相对隐蔽，不完成 TCP 连接，是**最常用**的扫描类型。
*   `-sT`: TCP Connect() 扫描。使用系统调用建立完整 TCP 连接。不需要 root 权限，但速度较慢，易被记录。
*   `-sU`: UDP 扫描。速度慢，且解释结果（open|filtered）可能困难。
*   `-sN`/`-sF`/`-sX`: TCP Null/FIN/Xmas 扫描。隐蔽扫描，利用某些系统对畸形 TCP 标志的响应来判断端口状态。对 Windows 系统通常无效。
*   `-sA`/`-sW`: TCP ACK/Window 扫描。主要用于探测防火墙规则集，判断端口是 `filtered`还是`unfiltered`。
*   `-sM`: TCP Maimon 扫描。类似 Null/FIN/Xmas，对某些 BSD 系统有效。
*   `--scanflags <flags>`: 自定义 TCP 标志进行扫描 (例如 `--scanflags URGACKPSHRSTSYNFIN`)。
*   `-b <FTP relay host>`: FTP bounce 扫描 (已很少使用)。
*   `-sO`: IP 协议扫描。探测目标支持哪些 IP 协议 (TCP, UDP, ICMP, IGMP 等)。

**4. 端口指定 (Port Specification):**

*   `-p <port ranges>`: 指定端口。例如：
    *   `-p 22` (单个端口)
    *   `-p 21,22,80,443` (端口列表)
    *   `-p 1-1024` (范围)
    *   `-p U:53,111,137,T:21-25,80,443` (指定 TCP/UDP 端口)
    *   `-p-` (扫描所有 65535 个端口)
*   `-F`: 快速模式。仅扫描 Nmap 内建的 100 个最常用端口。
*   `--top-ports <number>`: 扫描指定数量的最常用端口。
*   `-r`: 按顺序扫描端口，而不是默认的随机顺序。

**5. 服务与版本探测 (Service & Version Detection):**

*   `-sV`: 探测开放端口上运行的服务和版本信息。通常会强制进行 TCP 连接。
*   `--version-intensity <0-9>`: 设置版本探测强度 (0 最轻量，9 最全面，默认 7)。
*   `--version-light`: 等同于 `--version-intensity 2`。
*   `--version-all`: 等同于 `--version-intensity 9`。
*   `--version-trace`: 显示详细的版本探测活动。

**6. 操作系统探测 (OS Detection):**

*   `-O`: 启用操作系统探测。需要 root 权限。
*   `--osscan-limit`: 限制仅对满足“有开放和关闭的 TCP 端口”条件的主机进行 OS 探测。
*   `--osscan-guess` / `--fuzzy`: 猜测更接近的 OS 匹配，即使 Nmap 不完全确定。

**7. Nmap 脚本引擎 (NSE - Nmap Scripting Engine):**

*   `-sC`: 等同于 `--script=default`。运行默认类别的安全脚本，通常比较安全且信息量大。
*   `--script=<脚本类别,脚本文件名,脚本目录>`: 运行指定的脚本。例如：
    *   `--script=default,safe` (运行 default 和 safe 类别的脚本)
    *   `--script=vuln` (运行所有漏洞检测脚本)
    *   `--script=http-title` (运行单个脚本)
    *   `--script="http-*" `(运行所有 http 相关脚本)
    *   `--script=auth,discovery` (运行认证和发现类脚本)
*   **脚本类别示例:** `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`。
*   `--script-args <参数列表>`: 为 NSE 脚本传递参数 (例如 `--script-args user=admin,pass=password`)。
*   **漏洞扫描示例:**
    ```bash
    # 扫描常见漏洞
    nmap <target> --script=vuln
    # 扫描特定漏洞 (如 MS08-067, MS17-010)
    nmap <target> -p 445 --script=smb-vuln-ms08-067,smb-vuln-ms17-010
    # 尝试匿名 FTP 和常见 FTP 漏洞
    nmap <target> -p 21 --script=ftp-anon,ftp-vsftpd-backdoor,ftp-proftpd-backdoor
    ```
*   **暴力破解示例:** (需要配合字典参数)
    ```bash
    nmap <target> -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=passes.txt
    ```

**8. 时间和性能 (Timing & Performance):**

*   `-T<0-5>`: 设置时序模板 (影响扫描速度和隐蔽性)。
    *   `T0` (paranoid): 非常慢，用于 IDS 规避。
    *   `T1` (sneaky): 慢速。
    *   `T2` (polite): 降低速度以减少带宽和目标资源消耗。
    *   `T3` (normal): **默认**。
    *   `T4` (aggressive): 速度快，假设网络可靠。
    *   `T5` (insane): 非常快，可能牺牲准确性或淹没目标。
*   `--min-rate <number>` / `--max-rate <number>`: 控制每秒发送数据包的最小/最大速率。
*   `--min-parallelism <number>` / `--max-parallelism <number>`: 控制并行探测的数量（同时进行的探测）。
*   `--scan-delay <time>` / `--max-scan-delay <time>`: 控制探测之间的时间间隔。
*   `--host-timeout <time>`: 等待单个主机响应的最长时间 (例如 `30m`, `2h`)。

**9. 防火墙/IDS 规避与欺骗 (Firewall/IDS Evasion & Spoofing):**

*   `-f`: 使用小的分片 IP 数据包 (8 字节)。
*   `-ff`: 使用更小的分片 (16 字节)。
*   `--mtu <value>`: 自定义分片大小 (必须是 8 的倍数)。
*   `-D <decoy1,decoy2[,ME],...>`: 使用诱饵进行扫描。用逗号分隔的 IP 地址列表，`ME` 代表你的真实 IP 地址，`RND` 代表随机 IP。让扫描看起来像是来自多个源。
*   `-S <IP_Address>`: 伪造源 IP 地址。通常需要特殊权限且响应可能无法收到，除非你在同一网络或能控制路由。
*   `-e <interface>`: 指定使用的网络接口。
*   `--spoof-mac <MAC address, prefix, or vendor name>`: 伪造源 MAC 地址 (仅限局域网)。
*   `--data-length <number>`: 附加指定长度的随机数据到发送的数据包，可能用于绕过某些 IDS 检测。
*   `-sI <zombie host[:probeport]>`: Idle (僵尸) 扫描。一种极其隐蔽的扫描方式，利用一个空闲的主机作为跳板。需要找到合适的僵尸主机。
*   `--source-port <portnumber>` / `-g <portnumber>`: 使用指定的源端口。

**10. 输出选项 (Output):**

*   `-oN <filename>`: 标准输出 (Normal output) 保存到文件。
*   `-oX <filename>`: XML 输出保存到文件。便于程序解析。
*   `-oG <filename>`: Grepable 输出保存到文件。格式简单，便于 grep 等工具处理，但已不推荐。
*   `-oA <basename>`: 输出到所有主要格式 (Normal, XML, Grepable)，文件名为 `basename.nmap`, `basename.xml`, `basename.gnmap`。
*   `-v` / `-vv` / `-vvv`: 增加详细程度 (Verbosity)。显示更多扫描过程信息。
*   `-d` / `-dd`: 增加调试级别。输出非常详细的调试信息。
*   `--reason`: 显示端口处于特定状态（open, closed, filtered）的原因。
*   `--open`: 仅显示状态为 open 的端口。
*   `--packet-trace`: 显示所有发送和接收的数据包。用于深度调试。

**11. DNS 解析 (DNS Resolution):**

*   `-n`: **从不**进行 DNS 解析。扫描速度更快，尤其在目标网络 DNS 慢或不可靠时。
*   `-R`: **总是**进行 DNS 解析 (即使目标看起来离线)。
*   `--system-dns`: 使用操作系统的 DNS 解析器。
*   `--dns-servers <server1[,server2],...>`: 指定自定义 DNS 服务器。

**12. 其他选项 (Miscellaneous):**

*   `-A`: 启用 **Aggressive** 扫描选项。等同于 `-O -sV -sC --traceroute`。功能强大但动静较大。
*   `--traceroute`: 追踪到每个主机的网络路径。

## 注意事项 (Considerations)

*   **网络影响与检测:** 激进的扫描（高 `-T` 值、高并发）可能消耗大量带宽，影响目标网络性能，并极易触发入侵检测系统 (IDS) 或入侵防御系统 (IPS) 的警报或阻止。在生产环境或敏感网络中请谨慎使用 `-T4/T5` 和高并发设置。
*   **主机发现的局限性:**
    *   ARP 扫描 (`-PR`) 仅在同一广播域（局域网）内有效。扫描非同网段目标时，Nmap 会自动切换到其他发现方法。
    *   防火墙可能阻止 ICMP 或 TCP/UDP 探测包，导致 Nmap 误判主机为离线。此时必须使用 `-Pn` 强制扫描。
*   **扫描准确性:**
    *   操作系统 (`-O`) 和服务版本 (`-sV`) 的探测结果并非 100% 精确，有时会出错或无法确定。
    *   隐蔽扫描 (`-sN/sF/sX`) 的结果依赖于目标 TCP/IP 协议栈的实现，对某些系统（尤其是 Windows）无效或不准确。
    *   Idle 扫描 (`-sI`) 对僵尸主机的“空闲”状态要求很高，找到合适的僵尸主机可能很困难。
*   **防火墙/IDS 规避:** 现代防火墙和 IDS/IPS 非常复杂，简单的规避技术（如分片 `-f`, 诱饵 `-D`）可能效果有限或无效。需要结合多种技术和对目标环境的理解。
*   **输出管理:** 对于大型扫描，强烈建议使用 `-oN`, `-oX` 或 `-oA` 将结果保存到文件，便于后续分析。XML 格式 (`-oX`) 特别适合与其他工具集成。