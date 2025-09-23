#### 概述：TShark 与命令行工具 (Overview: TShark and Command-Line Tools)

**TShark** 是 Wireshark 的命令行版本，是一款功能强大的网络协议分析工具。它专为基于文本的分析而设计，非常适用于数据提取、深度数据包分析和自动化脚本。其强大的功能源于命令行的灵活性，因为其输出可以方便地通过管道 (`|`) 传递给其他工具进行进一步处理。

##### 辅助命令行工具 (Complementary Command-Line Tools)

|工具/实用程序|目的和优势|
|---|---|
|**`capinfos`**|提供捕获文件的摘要信息（如数据包数量、时长、平均速率等），建议在开始调查前使用。|
|**`grep`**|在纯文本数据中搜索特定模式或关键词。|
|**`cut`**|从文本行中按字段或字符提取特定部分。|
|**`uniq`**|过滤或统计文本中重复的行。|
|**`nl`**|为文本输出添加行号。|
|**`sed`**|一个强大的流编辑器，用于对文本进行复杂的转换。|
|**`awk`**|一种脚本语言，用于进行高级的模式搜索和数据处理。|

#### 1. TShark 主要参数 (Main TShark Parameters)

> **注意**：嗅探实时流量或列出网络接口通常需要超级用户权限 (`sudo`)。

##### 基本交互与嗅探 (Basic Interaction and Sniffing)

|参数|目的|示例|
|---|---|---|
|`-h`|显示帮助页面，列出最常用的功能。|`tshark -h`|
|`-v`|显示 TShark 的版本信息。|`tshark -v`|
|`-D`|列出所有可用的嗅探网络接口。|`sudo tshark -D`|
|`-i <interface>`|选择一个指定的接口来捕获实时流量。|`tshark -i 1` 或 `tshark -i eth0`|
|(无参数)|默认在第一个可用接口上嗅探流量，等同于 `tshark -i 1`。|`tshark`|

##### 读写文件与输出控制 (Reading/Writing Files and Output Control)

|参数|目的|示例|
|---|---|---|
|`-r <file>`|**读取 (Read)** 一个已保存的捕获文件（如 `.pcap`, `.pcapng`）。|`tshark -r demo.pcapng`|
|`-c <count>`|**计数 (Count)**，在读取或捕获指定数量的数据包后停止。|`tshark -r demo.pcapng -c 10`|
|`-w <file>`|**写入 (Write)**，将实时捕获的流量保存到一个文件中。|`tshark -w capture.pcap`|
|`-V`|**详细模式 (Verbose)**，为每个数据包提供完整的、类似 Wireshark“数据包详情面板”的解码信息。|`tshark -r demo.pcapng -V`|
|`-q`|**安静模式 (Quiet)**，在捕获时不在终端上实时打印数据包摘要。|`tshark -w capture.pcap -q`|
|`-x`|以**十六进制和 ASCII** 格式显示每个数据包的原始字节。|`tshark -r demo.pcapng -x`|

##### 捕获条件：自动停止与环形缓冲 (Capture Conditions: Autostop vs. Ring Buffer)

这些参数仅在实时捕获模式下（通常与 `-w` 结合使用）有效，用于控制捕获过程。

|参数|目的|示例|
|---|---|---|
|`-a <condition>`|**自动停止 (Autostop)**，在满足单个条件后**停止捕获**。||
||`duration:X`: 捕获 X 秒后停止。|`tshark -w test.pcap -a duration:60`|
||`filesize:X`: 捕获文件达到 X KB 后停止。|`tshark -w test.pcap -a filesize:1024`|
||`files:X`: 创建了 X 个文件后停止（需与 `-b` 结合使用）。|`tshark -w test.pcap -b filesize:1024 -a files:3`|
|`-b <condition>`|**环形缓冲 (Ring Buffer)**，在满足条件后**创建新文件并继续捕获**（可能形成无限循环）。||
||`duration:X`: 每隔 X 秒创建一个新文件。|`tshark -w test.pcap -b duration:60`|
||`filesize:X`: 当文件达到 X KB 时创建一个新文件。|`tshark -w test.pcap -b filesize:1024`|
||`files:X`: 最多创建 X 个文件，之后会覆盖最旧的文件。|`tshark -w test.pcap -b filesize:1024 -b files:3`|

#### 2. TShark 数据包过滤 (TShark Packet Filtering)

TShark 的过滤分为两种类型，使用不同的参数和语法。

##### 过滤选项概述 (Filtering Options Overview)

- **捕获过滤器 (Capture Filters)**: 在捕获**前**设置，用于**只保存**匹配特定条件的流量。
    
- **显示过滤器 (Display Filters)**: 在捕获**后**使用，用于在分析时**只显示**匹配特定条件的流量（隐藏不匹配的）。
    

|参数|过滤器类型|语法|
|---|---|---|
|`-f <expression>`|**捕获过滤器**|BPF (Berkeley Packet Filter) 语法|
|`-Y <expression>`|**显示过滤器**|Wireshark 显示过滤器语法|

##### 捕获过滤器详解 (`-f`) (Capture Filters in Detail)

捕获过滤器语法由限定符、方向和协议组成。

- **捕获过滤器语法 (Capture Filter Syntax)**:
    

|类别|详细信息和可用选项|示例|
|---|---|---|
|**限定符 (Qualifier)**|匹配类型。默认为 `host`。||
||`host`, `net`, `port`, `portrange`|`tshark -f "host 10.10.10.10"`|
|**方向 (Direction)**|流量方向。默认为源或目标。||
||`src`, `dst`|`tshark -f "src host 10.10.10.10"`|
|**协议 (Protocol)**|协议类型。||
||`arp`, `ether`, `icmp`, `ip`, `tcp`, `udp`|`tshark -f "tcp"`|

- **捕获过滤器实际应用 (Practical Capture Filter Examples)**:
    

|过滤类型|流量生成示例 (用于测试)|TShark 捕获过滤器命令|
|---|---|---|
|**主机过滤**|`curl tryhackme.com`|`tshark -f "host tryhackme.com"`|
|**IP 过滤**|`nc 10.10.10.10 4444 -vw 5`|`tshark -f "host 10.10.10.10"`|
|**端口过滤**|`nc 10.10.10.10 4444 -vw 5`|`tshark -f "port 4444"`|
|**协议过滤**|`nc -u 10.10.10.10 4444 -vw 5`|`tshark -f "udp"`|

#### 3. TShark 显示过滤器 (`-Y`) (TShark Display Filters)

显示过滤器使用与 Wireshark GUI 相同的强大语法，用于在分析已捕获或实时的数据时进行深度过滤。

##### 显示过滤器示例 (Display Filter Examples)

|类别|详细信息和可用选项|示例|
|---|---|---|
|**Protocol: IP**|过滤 IP 地址或范围。|`tshark -r file.pcap -Y 'ip.addr == 10.10.10.10'`|
|||`tshark -r file.pcap -Y 'ip.addr == 10.10.10.0/24'`|
|||`tshark -r file.pcap -Y 'ip.src == 10.10.10.10'`|
|**Protocol: TCP**|过滤 TCP 端口。|`tshark -r file.pcap -Y 'tcp.port == 80'`|
|||`tshark -r file.pcap -Y 'tcp.srcport == 80'`|
|**Protocol: HTTP**|过滤 HTTP 流量或响应码。|`tshark -r file.pcap -Y 'http'`|
|||`tshark -r file.pcap -Y "http.response.code == 200"`|
|**Protocol: DNS**|过滤 DNS 流量或查询类型。|`tshark -r file.pcap -Y 'dns'`|
|||`tshark -r file.pcap -Y 'dns.qry.type == 1'`|

> **提示**：要计算过滤后的数据包总数，可以将 TShark 的输出通过管道传递给 `nl` 命令，它会为每一行添加行号。

#### 4. TShark 统计功能 (`-z`) (TShark Statistics)

`-z` 参数是 TShark 中一个极其强大的功能，用于生成各种统计报告，类似于 Wireshark 的“统计”菜单。

- **`--color`**: 可以使用此参数来获得类似 Wireshark GUI 的彩色输出，便于阅读。
    
- **`-q` (安静模式)**: 与 `-z` 结合使用时，可以抑制原始数据包的输出，只显示最终的统计结果。
    
- **查看所有统计选项**:
    
    Bash
    
    ```
    tshark -z help
    ```
    

##### 协议层次结构 (Protocol Hierarchy)

- **命令**: `tshark -r file.pcap -z io,phs -q`
    
- **功能**: 以树状结构显示捕获文件中所有协议的分布情况，帮助分析师快速了解流量构成。
    

##### 数据包长度分布 (Packet Length Distribution)

- **命令**: `tshark -r file.pcap -z plen,tree -q`
    
- **功能**: 显示数据包按大小的分布情况，便于发现异常大或小的数据包。
    

##### 端点与会话 (Endpoints and Conversations)

- **端点**:
    
    - **命令**: `tshark -r file.pcap -z endpoints,ip -q`
        
    - **功能**: 列出所有唯一的端点（如 IP 地址）及其收发的数据包数量。
        
    - **可用协议**: `eth` (以太网), `ip`, `ipv6`, `tcp`, `udp`, `wlan`。
        
- **会话**:
    
    - **命令**: `tshark -r file.pcap -z conv,ip -q`
        
    - **功能**: 列出两个特定端点之间的所有会话。
        

##### 专家信息 (Expert Info)

- **命令**: `tshark -r file.pcap -z expert -q`
    
- **功能**: 显示 Wireshark 引擎对数据包的自动分析、警告和注释。
    

##### IPv4 与 IPv6 统计 (IPv4 and IPv6 Statistics)

- **协议类型分布**: `tshark -r file.pcap -z ptype,tree -q`
    
- **主机摘要 (IPv4)**: `tshark -r file.pcap -z ip_hosts,tree -q`
    
- **源/目标对 (IPv4)**: `tshark -r file.pcap -z ip_srcdst,tree -q`
    
- **出站流量 (IPv4)**: `tshark -r file.pcap -z dests,tree -q`
    

##### DNS 与 HTTP 统计 (DNS and HTTP Statistics)

- **DNS**: `tshark -r file.pcap -z dns,tree -q`
    
- **HTTP**:
    
    - **数据包和状态码计数**: `tshark -r file.pcap -z http,tree -q`
        
    - **负载分布**: `tshark -r file.pcap -z http_srv,tree -q`
        
    - **请求**: `tshark -r file.pcap -z http_req,tree -q`
        

#### 5. 高级数据提取 (Advanced Data Extraction)

##### 跟随流 (Following Streams)

类似于 Wireshark 的“Follow TCP Stream”，此功能可以重组并显示一个完整的会话内容。

|主要参数|协议|视图模式|流编号|附加参数|
|---|---|---|---|---|
|`-z follow`|`tcp`, `udp`, `http`, `http2`|`hex`, `ascii`|`0, 1, 2...`|`-q`|

- **示例 (跟随第一个 TCP 流)**:
    
    Bash
    
    ```
    tshark -r file.pcap -z follow,tcp,ascii,0 -q
    ```
    

##### 导出对象 (Exporting Objects)

TShark 可以自动从流量中提取通过特定协议传输的文件。

|主要参数|协议|目标文件夹|附加参数|
|---|---|---|---|
|`--export-objects`|`dicom`, `http`, `imf`, `smb`, `tftp`|`/path/to/folder`|`-q`|

- **示例 (从 HTTP 流量中提取所有文件)**:
    
    Bash
    
    ```
    tshark -r file.pcap --export-objects http,./extracted_files -q
    ```
    

##### 提取明文凭证 (Extracting Plaintext Credentials)

- **命令**: `tshark -r file.pcap -z credentials -q`
    
- **功能**: 自动检测并收集来自 FTP, HTTP, IMAP, POP, SMTP 等协议的明文凭证。
    

#### 6. 高级过滤与字段提取 (Advanced Filtering and Field Extraction)

##### 高级比较运算符 (`contains` vs. `matches`)

|过滤器|详细信息|
|---|---|
|**`contains`**|在数据包的特定字段内搜索一个**区分大小写**的子字符串。|
|**`matches`**|使用**不区分大小写**的正则表达式在字段内进行模式匹配。|

> **注意**: 这两个运算符不能用于值为整数的字段。

##### 提取特定字段 (`-T fields`)

这是 TShark 最强大的功能之一，允许你创建自定义的、类似 CSV 的输出，只显示你感兴趣的字段。

|主要参数|目标字段|显示字段名 (表头)|
|---|---|---|
|`-T fields`|`-e <field_name>`|`-E header=y`|

- **示例 (提取所有数据包的源 IP 和目标 IP)**:
    
    Bash
    
    ```
    tshark -r file.pcap -T fields -e ip.src -e ip.dst -E header=y
    ```
    

##### 高级过滤示例 (Advanced Filtering Examples)

- **`contains`**:
    
    - **目的**: 查找所有声称自己是 "Apache" 服务器的 HTTP 响应。
        
    - **过滤器**: `tshark -r file.pcap -Y 'http.server contains "Apache"'`
        
- **`matches`**:
    
    - **目的**: 查找所有对 `.php` 或 `.html` 页面的 HTTP 请求。
        
    - **过滤器**: `tshark -r file.pcap -Y 'http.request.uri matches "\.(php|html)"'`