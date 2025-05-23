### 1. 概述
`tcpdump` 是一个强大的命令行网络抓包工具，广泛用于捕获、分析和显示网络接口上的数据包。它允许用户根据各种条件过滤流量，并将捕获的数据保存到文件或实时显示。

### 2. 常用命令行参数
#### 概述
控制`tcpdump`基本行为的核心参数，如监听接口、读写文件、捕获数量和名称解析。
#### 参数
1.  **指定监听接口 (`-i`)**
    *   `-i <INTERFACE>`: 指定要监听的网络接口（如 `eth0`, `ens33`）。
    *   `-i any`: 监听所有活动的网络接口（需要较高权限，且可能无法在混杂模式下工作）。
    *   示例: `tcpdump -i eth0`
2.  **保存捕获数据包 (`-w`)**
    *   `-w <FILE>`: 将原始捕获的数据包写入指定文件（通常使用 `.pcap` 扩展名），而不是解析和打印到屏幕。
    *   示例: `tcpdump -i eth0 -w capture.pcap`
3.  **读取捕获文件 (`-r`)**
    *   `-r <FILE>`: 从指定文件中读取数据包进行分析和显示，而不是实时捕获。
    *   示例: `tcpdump -r capture.pcap`
4.  **限制捕获数量 (`-c`)**
    *   `-c <COUNT>`: 捕获指定数量的数据包后自动停止。
    *   示例: `tcpdump -i eth0 -c 100`
5.  **禁止名称解析 (`-n`, `-nn`)**
    *   `-n`: 不将IP地址反向解析为主机名。
    *   `-nn`: 不将IP地址解析为主机名，并且不将端口号解析为服务名。这可以加快处理速度并避免DNS查询。
    *   示例: `tcpdump -i eth0 -nn`
6.  **详细输出级别 (`-v`, `-vv`, `-vvv`)**
    *   `-v`, `-vv`, `-vvv`: 增加输出的详细程度。`-v` 提供更多信息（如TTL、IP ID），`-vv` 更详细，`-vvv` 最详细。
    *   示例: `tcpdump -i eth0 -vv`

### 3. 过滤表达式 (Primitives)
#### 概述
过滤表达式是`tcpdump`的核心，用于指定捕获或显示哪些数据包。基本原语包括类型（host, net, port）、方向（src, dst）和协议（proto）。
#### 原语
1.  **按主机过滤 (`host`, `src host`, `dst host`)**
    *   `host <IP或域名>`: 捕获源或目的地址是指定主机的数据包。
    *   `src host <IP或域名>`: 只捕获源地址是指定主机的数据包。
    *   `dst host <IP或域名>`: 只捕获目的地址是指定主机的数据包。
    *   示例: `tcpdump host 192.168.1.1`
    *   示例: `tcpdump src host 10.0.0.5`
2.  **按端口过滤 (`port`, `src port`, `dst port`)**
    *   `port <端口号>`: 捕获源或目的端口是指定端口的数据包。
    *   `src port <端口号>`: 只捕获源端口是指定端口的数据包。
    *   `dst port <端口号>`: 只捕获目的端口是指定端口的数据包。
    *   示例: `tcpdump port 80`
    *   示例: `tcpdump dst port 443`
3.  **按协议过滤 (`proto`)**
    *   可以指定协议名称，如 `tcp`, `udp`, `icmp`, `arp`, `ip`, `ip6` 等。
    *   示例: `tcpdump icmp`
    *   示例: `tcpdump -i eth0 tcp` (在eth0上只抓TCP包)

### 4. 组合过滤 (逻辑运算符)
#### 概述
使用逻辑运算符 `and` (或 `&&`), `or` (或 `||`), `not` (或 `!`) 可以将多个过滤原语组合起来，创建更复杂的过滤规则。可以使用括号 `()` 来控制优先级（注意可能需要Shell转义）。
#### 运算符
1.  **`and` / `&&`**: 同时满足两个条件。
    *   示例: `tcpdump src host 10.0.0.5 and dst port 80` (源IP是10.0.0.5且目的端口是80)
2.  **`or` / `||`**: 满足任意一个条件。
    *   示例: `tcpdump port 80 or port 443` (捕获HTTP或HTTPS流量)
3.  **`not` / `!`**: 不满足指定条件。
    *   示例: `tcpdump port 80 and not host 192.168.1.100` (捕获80端口流量，但排除主机192.168.1.100)
4.  **括号 `()`**: 控制运算优先级 (在Shell中常需要转义或引用)。
    *   示例: `tcpdump 'src host 10.0.0.1 and (dst port 80 or dst port 443)'` (源是10.0.0.1，且目的端口是80或443)

### 5. 高级过滤
#### 概述
除了基本的主机、端口和协议过滤，`tcpdump`还支持基于数据包长度和协议内部字段值的过滤。
#### 方法
1.  **按数据包长度过滤 (`greater`, `less`)**
    *   `greater <length>`: 捕获长度大于或等于指定字节数的数据包。
    *   `less <length>`: 捕获长度小于或等于指定字节数的数据包。
    *   示例: `tcpdump greater 1024` (捕获大于1KB的数据包)
2.  **按协议字段值过滤 (Byte Offsets)**
    *   语法: `proto[expr:size]`
        *   `proto`: 协议名 (如 `ether`, `ip`, `tcp`, `udp`, `icmp`)。
        *   `expr`: 相对于该协议头起始位置的字节偏移量 (从0开始)。
        *   `size`: 从偏移量开始检查的字节数 (通常是 1, 2, 或 4)。
    *   示例 (检查多播地址): `tcpdump 'ether[0] & 1 != 0'` (以太网头部第一个字节的最低位为1表示多播/广播)
    *   示例 (检查IP选项): `tcpdump 'ip[0] & 0xf != 5'` (IP头部第一个字节的低4位代表头部长度，不等于5表示包含IP选项)
3.  **按TCP标志位过滤 (`tcpflags`)**
    *   可以使用 `tcp-syn`, `tcp-ack`, `tcp-fin`, `tcp-rst`, `tcp-push`, `tcp-urg` 等关键字。
    *   语法: `tcp[tcpflags]` 结合位运算符 (`&`, `|`) 和比较运算符 (`==`, `!=`)。
    *   示例 (仅SYN包): `tcpdump 'tcp[tcpflags] == tcp-syn'` (只捕获仅设置了SYN标志的TCP包)
    *   示例 (含SYN包): `tcpdump 'tcp[tcpflags] & tcp-syn != 0'` (捕获设置了SYN标志的TCP包，可能同时设置了其他标志)
    *   示例 (含SYN或ACK包): `tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'` (捕获至少设置了SYN或ACK标志的包)

### 6. 输出格式控制
#### 概述
控制`tcpdump`输出信息详细程度和格式的参数。
#### 参数
1.  **简要输出 (`-q`)**
    *   `-q`: 输出更少的信息，通常只显示时间戳、协议、源/目的地址和端口。
2.  **打印链路层头部 (`-e`)**
    *   `-e`: 在输出行中包含数据链路层头部信息，通常是源和目的MAC地址。
3.  **显示数据包内容 (ASCII/Hex)**
    *   `-A`: 以ASCII格式打印每个数据包的内容（去除链路层头）。
    *   `-X`: 以十六进制和ASCII两种格式打印每个数据包的内容（去除链路层头）。
    *   `-xx`: 以十六进制格式打印每个数据包的内容（包括链路层头）。
    *   `-XX`: 以十六进制和ASCII两种格式打印每个数据包的内容（包括链路层头）。
    *   示例: `tcpdump -i eth0 -X port 80` (以Hex和ASCII显示HTTP流量内容)