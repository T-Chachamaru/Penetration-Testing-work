#### 概述：入侵检测与防御系统 (Overview: Intrusion Detection & Prevention Systems)

##### 入侵检测系统 (IDS - Intrusion Detection System)

IDS 是一种**被动监控**解决方案，用于检测可能的恶意活动、异常事件和策略违规。当检测到可疑事件时，它的主要职责是**生成警报**。

- **主要类型**:
    
    - **网络入侵检测系统 (NIDS)**: 监控整个网络或子网的流量，以发现可疑模式。
        
    - **基于主机的入侵检测系统 (HIDS)**: 监控单个终端设备的流量和系统活动。
        

##### 入侵防御系统 (IPS - Intrusion Prevention System)

IPS 是一种**主动保护**解决方案，它不仅检测威胁，还会**立即采取行动**（如阻止、预防或终止连接）来防止攻击发生。

- **主要类型**:
    
    - **网络入侵防御系统 (NIPS)**: 主动保护整个网络或子网的流量，在识别到威胁时终止恶意连接。
        
    - **基于行为的入侵防御系统 (NBA)**: 也称为网络行为分析系统。它通过学习网络的“正常”流量模式（建立基线），来识别和阻止异常或未知的威胁。
        
    - **无线入侵防御系统 (WIPS)**: 专门监控无线网络流量，以保护 Wi-Fi 环境并阻止相关攻击。
        
    - **基于主机的入侵防御系统 (HIPS)**: 主动保护单个终端设备，在识别到威胁时终止恶意进程或连接。
        

##### 检测/预防技术 (Detection/Prevention Technologies)

- **基于签名 (Signature-based)**: 依赖预定义的规则库来识别已知的攻击模式。
    
- **基于行为 (Behavior-based)**: 通过将当前活动与已建立的“正常”行为基线进行比较，来识别未知或新的威胁。
    
- **基于策略 (Policy-based)**: 将检测到的活动与预设的系统安全策略进行比较，以发现违规行为。
    

#### Snort：开源 NIDS/NIPS 解决方案 (Snort: An Open-Source NIDS/NIPS Solution)

**Snort** 是一个基于规则的开源网络入侵检测和防御系统 (NIDS/NIPS)，由 Martin Roesch、开源社区和 Cisco Talos 团队共同开发维护。

##### Snort 的功能

- 实时流量分析
    
- 攻击与探测检测
    
- 数据包记录
    
- 协议分析
    
- 实时警报
    
- 模块化与插件化
    
- 预处理器
    
- 跨平台支持
    

##### Snort 的三种主要模式 (The Three Main Modes of Snort)

1. **嗅探模式 (Sniffer Mode)**: 像 `tcpdump` 一样读取并显示网络数据包。
    
2. **数据包记录模式 (Packet Logger Mode)**: 将网络流量记录到磁盘文件中。
    
3. **NIDS/IPS 模式 (NIDS/IPS Mode)**: 根据规则集分析网络流量，并执行记录或丢弃数据包等操作。
    

#### Snort 交互与配置 (Snort Interaction and Configuration)

|命令/参数|描述|
|---|---|
|`snort -V`|验证 Snort 是否已安装并显示版本信息。|
|`snort -T`|测试配置文件 (`snort.conf`) 的语法是否有效。|
|`snort -c <path>`|指定要使用的配置文件。这是运行 NIDS/IPS 模式的核心参数。|
|`snort -q`|安静模式，禁止显示启动横幅和初始信息。|

- **配置文件检查示例**:
    
    Bash
    
    ```
    sudo snort -c /etc/snort/snort.conf -T
    ```
    

配置文件 (`snort.conf`) 是 Snort 的大脑，其中定义了规则、插件、检测机制、默认操作和输出设置。

#### Snort 模式详解 (Snort Modes in Detail)

##### 1. 嗅探模式 (Sniffer Mode)

|参数|描述|
|---|---|
|`-v`|详细模式，在控制台显示 TCP/IP 输出。|
|`-d`|显示数据包的有效载荷 (payload)。|
|`-e`|显示链路层（第二层）头部信息。|
|`-X`|以十六进制和 ASCII 格式显示完整的原始数据包。|
|`-i <interface>`|指定要监听的网络接口（如 `eth0`）。|

##### 2. 数据包记录模式 (Packet Logger Mode)

|参数|描述|
|---|---|
|`-l <dir>`|启用日志记录模式，并将日志文件保存到指定目录。默认为 `/var/log/snort`。|
|`-K ASCII`|以 ASCII 格式记录数据包，便于人类阅读。|
|`-r <logfile>`|读取模式，用于分析已记录的 Snort 日志文件。|
|`-n <number>`|与 `-r` 配合使用，指定只处理前 n 个数据包。|

- **读取并过滤日志**: `-r` 参数可以与 BPF (Berkeley Packet Filter) 语法结合，用于从日志文件中筛选特定的流量。
    
    Bash
    
    ```
    # 从日志文件中只读取 UDP 端口 53 的流量
    sudo snort -dvr logname.log 'udp and port 53'
    ```
    

> **日志文件所有权**: 由于 Snort 需要 root 权限运行，它生成的日志文件所有者也是 `root`。因此，你需要 `sudo` 权限才能读取和分析这些日志。

##### 3. NIDS/IPS 模式 (NIDS/IPS Mode)

|参数|描述|
|---|---|
|`-c <conf_file>`|指定配置文件，激活 NIDS/IPS 模式。|
|`-T`|测试配置文件并退出。|
|`-N`|禁用日志记录。|
|`-D`|在后台（守护进程）模式下运行 Snort。|
|`-A <mode>`|设置警报模式。|

- **警报模式 (`-A`) 选项**:
    
    - `full`: 默认模式，提供最详细的警报信息。
        
    - `fast`: 快速模式，只显示时间戳、源/目标 IP 和端口等关键信息。
        
    - `console`: 在控制台实时显示快速风格的警报。
        
    - `cmg`: CMG 风格，显示基本头部信息和十六进制/文本格式的 payload。
        
    - `none`: 禁用警报。
        
- **激活 IPS 模式**:
    
    Bash
    
    ```
    # 使用 afpacket DAQ 模块，并在 eth0 和 eth1 之间进行内联拦截
    sudo snort -Q --daq afpacket -i eth0:eth1 -c /etc/snort/snort.conf -A console
    ```
    

#### 使用 Snort 进行 PCAP 调查 (PCAP Investigation with Snort)

Snort 也可以直接分析 PCAP 文件，这对于离线调查非常有用。

|参数|描述|
|---|---|
|`-r <pcap_file>`|读取单个 pcap 文件进行分析。|
|`--pcap-list "<file1> <file2>"`|读取一个以空格分隔的 pcap 文件列表。|
|`--pcap-show`|在处理时，在控制台上显示当前正在分析的 pcap 文件名。|

#### Snort 规则 (Snort Rules)

Snort 的核心在于其规则。虽然理解规则结构很重要，但在实际工作中，无需从头记忆所有细节。可以参考 `/etc/snort/snort.conf` 配置文件中的示例，并利用 AI 工具或社区资源来辅助编写和分析 IDS/IPS 规则。