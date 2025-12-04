#### 1. 网络监控 vs. 网络安全监控 (Network Monitoring vs. NSM)

##### 网络监控 (Network Monitoring)

网络监控是一系列管理操作，旨在持续观察网络流量以检测和减少网络问题、提高性能。

- **关注点**: 主要关注 IT 资产的**可用性**（正常运行时间）、**性能**（设备健康、连接质量）和**配置**（流量平衡）。
    
- **职责**: 通常由企业的 IT 或网络管理团队负责，不属于 SOC 的范畴。
    

##### 网络安全监控 (Network Security Monitoring, NSM)

网络安全监控专注于识别网络中的安全异常和威胁。

- **关注点**: 关注**安全异常**，如未授权主机、可疑服务和端口使用、加密流量中的恶意模式以及入侵检测与响应。
    
- **职责**: 是 SOC 的核心职能，由各级安全分析师执行。
    

#### 2. Zeek 简介 (Introduction to Zeek)

##### 什么是 Zeek？

**Zeek** (前身为 Bro) 是一个开源的被动网络流量分析框架。它与传统的 IDS/IPS 不同，其核心功能是生成**极其详细且结构化的网络活动日志**，这些日志既可用于实时的安全监控，也可用于事后的深度取证调查。目前，Zeek 提供了 7 个类别下的 50 多种日志。

##### Zeek vs. Snort

|特性|**Zeek**|**Snort**|
|---|---|---|
|**定位/功能**|NSM 和 IDS 框架，专注于**深度网络分析**和**事件**检测。|IDS/IPS 系统，专注于使用**签名**来检测已知的漏洞和攻击。|
|**优点**|提供深入的流量可见性；适用于威胁狩猎；能检测复杂威胁；拥有脚本语言支持事件关联。|规则易于编写；Cisco Talos 和社区支持强大；日志易于阅读。|
|**缺点**|使用门槛较高；分析通常在 Zeek 之外进行（手动或自动化）。|难以检测复杂或未知的威胁。|
|**常见用例**|网络监控；深度流量调查；检测链式攻击事件。|入侵检测与防御；阻止已知的攻击和威胁。|

##### Zeek 架构 (Zeek Architecture)

1. **事件引擎 (Event Engine)**: Zeek 的核心，负责处理原始数据包，将其解析为协议无关的事件（如 `http_request`, `new_connection`），但不关心事件的语义。
    
2. **策略脚本解释器 (Policy Script Interpreter)**: 负责执行 Zeek 脚本。这些脚本定义了如何响应事件引擎生成的事件，从而实现语义分析、日志记录、触发警报等高级功能。
    

##### Zeek 框架 (Zeek Frameworks)

Zeek 通过多个框架来扩展其功能，使其更加灵活和强大。

- 日志记录 (Logging)
    
- 注意 (Notice)
    
- 输入 (Input)
    
- 配置 (Configuration)
    
- 情报 (Intelligence)
    
- 集群 (Cluster)
    
- 文件分析 (File Analysis)
    
- 签名 (Signature)
    
- 数据包分析 (Packet Analysis)
    
- TLS 解密 (TLS Decryption)
    
- 等等...
    

#### 3. 使用 Zeek (Using Zeek)

##### 运行模式 (Operating Modes)

1. **作为服务运行**: 使用 `ZeekControl` 模块来实时监控网络接口的流量。
    
2. **处理 PCAP 文件**: 在命令行中直接对已捕获的 PCAP 文件进行离线分析。
    

##### ZeekControl：管理 Zeek 服务

`ZeekControl` 模块用于管理实时监控服务，需要 root 权限。

- **常用命令**:
    
    Bash
    
    ```
    # 检查 Zeek 服务状态
    sudo zeekctl status
    
    # 启动 Zeek 服务
    sudo zeekctl start
    
    # 停止 Zeek 服务
    sudo zeekctl stop
    ```
    
- **日志路径**: 作为服务运行时，日志默认生成在 `/opt/zeek/logs/`。
    

##### 命令行参数 (Command-Line Parameters)

|参数|描述|
|---|---|
|`-r <file>`|读取并处理一个 PCAP 文件。|
|`-C`|忽略 TCP 校验和错误。|
|`-v`|显示版本信息。|
|`zeekctl`|启动 ZeekControl 管理模块。|

- **处理 PCAP 文件示例**:
    
    Bash
    
    ```
    zeek -r traffic.pcap
    ```
    
    处理完成后，日志文件会生成在当前工作目录中。
    

#### 4. Zeek 日志详解 (Zeek Logs in Detail)

##### 日志结构与输出

Zeek 的日志是结构化的、以**制表符分隔**的 ASCII 文件，非常便于命令行工具处理。所有相关的事件和连接都通过一个名为 **UID** 的唯一标识符进行关联。

##### 日志文件分类 (Log File Categories)

|类别|描述|部分日志文件示例|
|---|---|---|
|**Network**|网络协议日志|`conn.log`, `dhcp.log`, `dns.log`, `http.log`, `ssh.log`, `ssl.log`...|
|**Files**|文件分析结果日志|`files.log`, `ocsp.log`, `pe.log`, `x509.log`...|
|**NetControl**|网络控制和流量日志|`netcontrol.log`, `openflow.log`...|
|**Detection**|检测和可能的指示日志|`intel.log`, `notice.log`, `signatures.log`...|
|**Network Observations**|网络流量观察日志|`known_certs.log`, `known_hosts.log`, `known_services.log`, `software.log`...|
|**Miscellaneous**|外部警报、输入和故障等|`dpd.log`, `weird.log`...|
|**Zeek Diagnostic**|Zeek 自身的诊断日志|`capture_loss.log`, `loaded_scripts.log`, `stats.log`...|

##### 关键日志更新频率 (Key Log Update Frequency)

|更新频率|日志名称|描述|
|---|---|---|
|每日|`known_hosts.log`|记录已完成 TCP 握手的主机列表。|
|每日|`known_services.log`|记录主机使用的服务列表。|
|每日|`known_certs.log`|记录观察到的 SSL 证书列表。|
|每日|`software.log`|记录网络中观察到的软件列表。|
|按会话|`notice.log`|记录 Zeek 检测到的异常或值得注意的事件。|
|按会话|`intel.log`|记录与威胁情报匹配的流量。|
|按会话|`signatures.log`|记录触发了 Zeek 签名的事件。|

##### 日志调查工作流 (Log Investigation Workflow)

一个有效的调查流程可以从宏观到微观，逐步深入。

|步骤|目的|关注的日志|
|---|---|---|
|1. **总体信息**|审查整体连接、文件传输和指标，建立初步概览。|`conn.log`, `files.log`, `intel.log`, `loaded_scripts.log`|
|2. **基于协议**|发现可疑指标后，深入分析特定协议的流量。|`http.log`, `dns.log`, `ftp.log`, `ssh.log`|
|3. **检测**|查看由脚本和签名生成的具体检测结果，为发现提供证据。|`notice.log`, `signatures.log`, `pe.log`|
|4. **观察**|总结主机、服务和软件信息，发现可能的遗漏点并得出结论。|`known_host.log`, `known_services.log`, `software.log`, `weird.log`|

#### 5. 处理和分析 Zeek 日志 (Processing and Analyzing Zeek Logs)

在处理大量 Zeek 日志时，命令行工具的效率远超图形界面。

##### `zeek-cut`：提取日志列

`zeek-cut` 是一个辅助程序，可以方便地从日志文件中提取指定的列（字段）。

Bash

```
# 从 conn.log 中提取 UID, 协议, 源/目标 IP 和端口
cat conn.log | zeek-cut uid proto id.orig_h id.orig_p id.resp_h id.resp_p
```

##### 核心命令行工具 (Core Command-Line Tools)

|类别|命令与用法示例|
|---|---|
|**Basics**|`history` (查看历史), `!10` (执行第10条历史命令), `!!` (执行上一条命令)|
|**Read File**|`cat`, `head`, `tail`|
|**Find & Filter**|`cut` (按字段/列切分), `grep` (过滤关键词), `sort` (排序), `uniq` (去重), `wc` (计数), `nl` (显示行号)|
|**Advanced**|`sed` (按行号打印), `awk` (按条件打印)|
|**Special**|`zeek-cut` (按 Zeek 字段名提取)|

##### 常用命令链 (Common Command Chains)

|命令链|用途|
|---|---|
|`sort|uniq`|
|`sort|uniq -c`|
|`sort -nr`|按数值进行降序排序。|
|`grep -v 'test'`|显示所有**不**包含 "test" 字符串的行（反向过滤）。|
|`cut -d '.' -f 1-2`|使用 `.` 作为分隔符，切分字符串并保留前两个字段。|

#### 6. Zeek 签名 (Zeek Signatures)

Zeek 支持使用签名（规则）来进行低级的模式匹配，其功能与 Snort 规则类似。但与 Snort 不同，签名并非 Zeek 的主要检测手段，而是其强大脚本语言的补充，用于发现和关联网络上的重要活动。

- **签名结构**:
    
    1. **规则 ID (Signature ID)**: 一个唯一的签名名称。
        
    2. **条件 (Conditions)**: 定义了匹配数据包头部或负载的模式。
        
    3. **动作 (Action)**: 定义了匹配成功后要执行的操作，默认为在 `signatures.log` 中生成一条记录。
        

##### 签名条件与过滤器 (Signature Conditions and Filters)

|条件字段|可用过滤器|
|---|---|
|**Header (头部)**|`src-ip`, `dst-ip`, `src-port`, `dst-port`, `ip-proto` (TCP, UDP, ICMP, etc.)|
|**Content (内容)**|`payload`, `http-request`, `http-request-header`, `http-request-body`, `http-reply-header`, `http-reply-body`, `ftp`|
|**Context (上下文)**|`same-ip` (过滤源/目标地址相同的流量)|
|**Action (动作)**|`event` (定义签名匹配时生成的消息)|
|**Comparison (比较)**|`==`, `!=`, `<`, `<=`, `>`, `>=` (支持字符串、数字和正则表达式)|

##### 使用签名 (Using Signatures)

Zeek 签名使用 `.sig` 扩展名，并通过 `-s` 参数在命令行中调用。

Bash

```
zeek -C -r sample.pcap -s sample.sig
```

##### 示例 1：检测明文密码提交

这条签名用于检测 HTTP 流量中任何包含 "password" 字符串的数据包。

Code snippet

```
signature http-password {
    ip-proto == tcp
    dst-port == 80
    payload /.*password.*/
    event "Cleartext Password Found!"
}
```

- **分析**: 当此签名匹配时，Zeek 会在 `signatures.log` 和 `notice.log` 中生成警报。
    

##### 示例 2：检测 FTP 暴力破解

我们可以创建多个签名并将它们保存在同一个 `.sig` 文件中。

1. **检测 "admin" 登录尝试**:
    
    Code snippet
    
    ```
    signature ftp-admin {
        ip-proto == tcp
        ftp /.*USER.*dmin.*/
        event "FTP Admin Login Attempt!"
    }
    ```
    
2. **检测所有失败的登录尝试** (更通用):
    
    Code snippet
    
    ```
    signature ftp-brute {
        ip-proto == tcp
        payload /.*530.*Login.*incorrect.*/
        event "FTP Brute-force Attempt"
    }
    ```
    

#### 7. Zeek 脚本基础 (Zeek Scripting Basics)

Zeek 拥有自己的**事件驱动 (event-driven)** 脚本语言，其功能强大，允许分析师对检测到的事件进行复杂的调查和关联。

##### 脚本文件位置 (Script File Locations)

- **基础脚本 (Base)**: `/opt/zeek/share/zeek/base` (不应修改)
    
- **用户/站点脚本 (Site)**: `/opt/zeek/share/zeek/site` (用于存放用户自定义或修改的脚本)
    
- **策略脚本 (Policy)**: `/opt/zeek/share/zeek/policy`
    

##### 加载脚本 (Loading Scripts)

- **实时监控模式**: 在 `/opt/zeek/share/zeek/site/local.zeek` 配置文件中使用 `@load` 指令来自动加载脚本。
    
- **单次运行模式**: 在命令行中直接指定要运行的 `.zeek` 脚本文件。
    

##### 脚本的优势：自动化任务

Zeek 脚本可以用极少的代码实现其他工具需要复杂命令链才能完成的任务。

- **示例：提取 DHCP 主机名**
    
    - **使用 `tcpdump` 和 `awk`**:
        
        Bash
        
        ```
        sudo tcpdump -ntr smallFlows.pcap port 67 or port 68 -e -vv | grep 'Hostname Option' | awk -F: '{print $2}' | sort -nr | uniq | nl
        ```
        
    - **使用 Zeek 脚本**:
        
        Code snippet
        
        ```
        event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
            {
            print options$host_name;
            }
        ```
        
        **运行**: `zeek -C -r smallFlows.pcap dhcp-hostname.zeek`
        

#### 8. Zeek 脚本进阶 (Advanced Zeek Scripting)

##### 基本事件：`zeek_init` 与 `zeek_done`

这两个事件分别在 Zeek 进程启动和结束时触发，常用于初始化或总结任务。

Code snippet

```
event zeek_init()
    {
    print ("Started Zeek!");
    }

event zeek_done()
    {
    print ("Stopped Zeek!");
    }
```

##### 事件驱动：处理新连接

`new_connection` 事件会在每个新 TCP 连接建立时触发。我们可以利用它来提取和格式化连接的详细信息。

Code snippet

```
event new_connection(c: connection)
    {
    print ("###########################################################");
    print ("New Connection Found!");
    # c$id$orig_h: 连接发起方的主机 (IP) 地址
    # c$id$orig_p: 连接发起方的端口
    # c$id$resp_h: 连接响应方的主机 (IP) 地址
    # c$id$resp_p: 连接响应方的端口
    print fmt ("Source Host: %s # %s --->", c$id$orig_h, c$id$orig_p);
    print fmt ("Destination Host: %s # %s <---", c$id$resp_h, c$id$resp_p);
    print ("");
    }
```

##### 结合脚本与签名 (Combining Scripts and Signatures)

Zeek 脚本可以响应签名匹配事件，实现更高级的逻辑。

- **`signature_match` 事件**: 当任何签名被触发时，此事件就会被调用。
    
- **示例**: 创建一个脚本，当 `ftp-admin` 签名被触发时，在终端打印一条特定消息。
    
    Code snippet
    
    ```
    event signature_match (state: signature_state, msg: string, data: string)
        {
        if (state$sig_id == "ftp-admin")
            {
            print ("Signature hit! --> #FTP-Admin ");
            }
        }
    ```
    

#### 9. Zeek 框架与包 (Zeek Frameworks and Packages)

##### 使用框架 (Using Frameworks)

Zeek 提供了超过 15 个框架，这些是预构建的脚本集合，用于实现特定功能。

- **文件框架 (Files Framework)**:
    
    - **计算哈希**: 运行此脚本会自动为流量中提取的所有文件计算 MD5, SHA1 和 SHA256 哈希值，并记录在 `files.log` 中。
        
        Bash
        
        ```
        zeek -C -r case1.pcap /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek
        ```
        
    - **提取文件**: 运行此脚本会自动将流量中传输的所有文件提取并保存到 `extract_files` 目录中。
        
        Bash
        
        ```
        zeek -C -r case1.pcap /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek
        ```
        
- **情报框架 (Intelligence Framework)**:
    
    - **功能**: 将网络流量与一个或多个威胁情报源进行匹配。
        
    - **工作流程**:
        
        1. 创建一个制表符分隔的情报文件 (如 `zeek_intel.txt`)。
            
        2. 创建一个 Zeek 脚本，使用 `@load` 加载情报框架，并指定情报文件路径。
            
        3. 运行 Zeek。当流量中的指标（如域名、IP）与情报文件匹配时，会在 `intel.log` 中生成警报。
            

##### 使用包管理器 (`zkg`)

**`zkg`** 是 Zeek 的包管理器，用于轻松安装和管理第三方脚本和插件。

|命令|描述|
|---|---|
|`zkg install <package>`|安装一个包。|
|`zkg list`|列出所有已安装的包。|
|`zkg remove <package>`|移除一个已安装的包。|
|`zkg refresh`|检查已安装包的更新。|
|`zkg upgrade`|更新所有已安装的包。|

- **示例包 1：明文密码嗅探 (`zeek-sniffpass`)**:
    
    1. 安装: `sudo zkg install zeek/cybera/zeek-sniffpass`
        
    2. 使用（三种方式）:
        
        Bash
        
        ```
        # 通过自定义脚本 @load
        zeek -Cr http.pcap sniff-demo.zeek
        # 通过完整路径
        zeek -Cr http.pcap /opt/zeek/share/zeek/site/zeek-sniffpass
        # 直接通过包名 (最常用)
        zeek -Cr http.pcap zeek-sniffpass
        ```
        
- **示例包 2：地理位置信息 (`geoip-conn`)**:
    
    - **功能**: 安装后，此包会自动为 `conn.log` 文件中的 IP 地址添加地理位置信息（国家、城市等）。