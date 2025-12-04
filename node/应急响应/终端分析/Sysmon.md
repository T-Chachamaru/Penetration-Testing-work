#### 概述 (Overview)

**Sysmon (System Monitor)** 是 Windows Sysinternals 套件中的一款核心工具。它作为一个系统服务和设备驱动程序运行，用于监控和记录系统活动到 Windows 事件日志中。与标准的 Windows 事件日志相比，Sysmon 提供了**更详细、高质量**的日志信息和**更精细的配置控制**，是进行深度威胁狩猎和应急响应的基石。

##### 什么是 Sysmon？

Sysmon 记录关于进程创建、网络连接、文件创建时间变更等详细信息。这些日志通常会被转发到 SIEM (安全信息和事件管理) 系统中进行聚合、关联和可视化分析，帮助分析师识别恶意或异常活动。

##### 日志位置 (Log Location)

Sysmon 的事件日志存储在事件查看器的以下路径：

Applications and Services Logs/Microsoft/Windows/Sysmon/Operational

#### 1. Sysmon 配置详解 (Sysmon Configuration in Detail)

Sysmon 的强大之处在于其灵活的 **XML 配置文件**。该文件精确地告诉 Sysmon 应该记录什么、忽略什么。

- **排除 (Exclude) vs. 包含 (Include)**:
    
    - **排除规则**: 配置文件通常以大量的**排除规则**为主，旨在过滤掉环境中的正常活动（“噪音”），使分析师能专注于真正可疑的事件。这是最常见的配置策略。
        
    - **包含规则**: 也可以采取更主动的方法，使用**包含规则**来明确指定要监控的已知恶意行为模式。
        

##### 关键事件 ID 详解 (Key Event IDs Explained)

Sysmon 包含超过 29 种事件 ID，以下是一些在威胁狩猎中最常用的事件 ID。

- **Event ID 1：进程创建 (Process Create)**
    
    - **功能**: 记录系统中每一个进程的创建事件，包括其完整的命令行、哈希值和父进程信息。
        
    - **示例**: 排除一个已知的、正常的 `svchost.exe` 命令行，以减少噪音。
        
        XML
        
        ```
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="exclude">
                <CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>
            </ProcessCreate>
        </RuleGroup>
        ```
        
- **Event ID 3：网络连接 (Network Connect)**
    
    - **功能**: 记录所有出站网络连接，包括发起连接的进程、源/目标 IP 和端口等。
        
    - **示例**: 包含所有由 `nmap.exe` 发起的连接，或任何连接到 Metasploit 常用端口 `4444` 的连接。
        
        XML
        
        ```
        <RuleGroup name="" groupRelation="or">
            <NetworkConnect onmatch="include">
                <Image condition="image">nmap.exe</Image>
                <DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>
            </NetworkConnect>
        </RuleGroup>
        ```
        
- **Event ID 7：映像加载 (Image Load)**
    
    - **功能**: 记录进程加载的 DLL。可用于追踪 DLL 注入和劫持攻击，但此事件会产生大量日志，需谨慎使用。
        
    - **示例**: 包含所有从临时目录 (`\Temp\`) 加载的 DLL，这通常是可疑行为。
        
        XML
        
        ```
        <RuleGroup name="" groupRelation="or">
            <ImageLoad onmatch="include">
                <ImageLoaded condition="contains">\Temp\</ImageLoaded>
            </ImageLoad>
        </RuleGroup>
        ```
        
- **Event ID 8：创建远程线程 (Create Remote Thread)**
    
    - **功能**: 监控一个进程向另一个进程注入代码的行为，这是恶意软件隐藏其活动和横向移动的常用技术。
        
    - **示例**: 包含所有注入的、起始内存地址以 `0B80` 结尾（可能是 Cobalt Strike 的特征）的线程。
        
        XML
        
        ```
        <RuleGroup name="" groupRelation="or">
            <CreateRemoteThread onmatch="include">
                <StartAddress name="Alert,Cobalt Strike" condition="end with">0B80</StartAddress>
                <SourceImage condition="contains">\</SourceImage>
            </CreateRemoteThread>
        </RuleGroup>
        ```
        
- **Event ID 11：文件创建 (File Create)**
    
    - **功能**: 记录磁盘上文件的创建事件。
        
    - **示例**: 包含所有文件名中含有 `HELP_TO_SAVE_FILES` 的文件创建事件，这是勒索软件赎金信的常见模式。
        
        XML
        
        ```
        <RuleGroup name="" groupRelation="or">
            <FileCreate onmatch="include">
                <TargetFilename name="Alert,Ransomware" condition="contains">HELP_TO_SAVE_FILES</TargetFilename>
            </FileCreate>
        </RuleGroup>
        ```
        
- **Event ID 12/13/14：注册表事件 (Registry Event)**
    
    - **功能**: 检测注册表的创建、修改或删除，常用于监控持久化和凭证滥用。
        
    - **示例**: 包含所有针对 `Windows\System\Scripts` 路径的注册表修改，这是攻击者放置持久化脚本的常见位置。
        
        XML
        
        ```
        <RuleGroup name="" groupRelation="or">
            <RegistryEvent onmatch="include">
                <TargetObject name="T1484" condition="contains">Windows\System\Scripts</TargetObject>
            </RegistryEvent>
        </RuleGroup>
        ```
        
- **Event ID 15：文件流创建 (File Create Stream Hash)**
    
    - **功能**: 检测在**替代数据流 (Alternate Data Streams, ADS)** 中创建的文件，这是攻击者隐藏恶意软件的常用技术。
        
    - **示例**: 包含所有在 ADS 中创建的、以 `.hta` 结尾的文件。
        
        XML
        
        ```
        <RuleGroup name="" groupRelation="or">
            <FileCreateStreamHash onmatch="include">
                <TargetFilename condition="end with">.hta</TargetFilename>
            </FileCreateStreamHash>
        </RuleGroup>
        ```
        
- **Event ID 22：DNS 事件 (DNS Event)**
    
    - **功能**: 记录所有 DNS 查询和响应。
        
    - **示例**: 排除所有对 `microsoft.com` 域的查询，以减少噪音。
        
        XML
        
        ```
        <RuleGroup name="" groupRelation="or">
            <DnsQuery onmatch="exclude">
                <QueryName condition="end with">.microsoft.com</QueryName>
            </DnsQuery>
        </RuleGroup>
        ```
        

#### 2. 安装与使用 (Installation and Usage)

##### 安装 Sysmon

1. **下载工具**: 从微软官网或通过 PowerShell (`Download-SysInternalsTools C:\Sysinternals`) 下载 Sysmon。
    
2. **获取配置文件**: 下载一个社区维护的优秀配置文件，例如 [SwiftOnSecurity 的 sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)。
    

##### 启动 Sysmon

以管理员身份打开 PowerShell 或命令提示符，使用 `-i` 参数安装 Sysmon 服务并应用配置文件。

Bash

```
# 假设 Sysmon.exe 和配置文件位于同一目录下
Sysmon.exe -accepteula -i swift.xml
```

#### 3. 日志分析与最佳实践 (Log Analysis and Best Practices)

- **排除 > 包含**: 优先使用排除规则来过滤已知正常行为，这比只包含已知恶意行为更有效。
    
- **命令行优先**: `Get-WinEvent` 和 `wevtutil.exe` 提供了比事件查看器 GUI 更强大的筛选能力。
    
- **了解你的环境**: 在制定规则前，必须了解环境的基线，才能有效地区分正常与异常。
    

#### 4. 威胁狩猎实战 (Practical Threat Hunting)

##### 追踪 Metasploit

- **假设**: Metasploit 的 meterpreter shell 通常使用默认端口（如 `4444`, `5555`）进行 C2 通信。
    
- **配置**:
    
    XML
    
    ```
    <RuleGroup name="" groupRelation="or">
        <NetworkConnect onmatch="include">
            <DestinationPort condition="is">4444</DestinationPort>
            <DestinationPort condition="is">5555</DestinationPort>
        </NetworkConnect>
    </RuleGroup>
    ```
    
- **PowerShell 查询**:
    
    PowerShell
    
    ```
    Get-WinEvent -Path <Path_to_Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'
    ```
    

##### 检测 Mimikatz

- **假设**: Mimikatz 会访问 `lsass.exe` 进程来转储凭证。
    
- **配置**:
    
    XML
    
    ```
    <RuleGroup name="" groupRelation="or">
        <ProcessAccess onmatch="exclude">
            <SourceImage condition="image">svchost.exe</SourceImage>
        </ProcessAccess>
        <ProcessAccess onmatch="include">
            <TargetImage condition="image">lsass.exe</TargetImage>
        </ProcessAccess>
    </RuleGroup>
    ```
    
- **PowerShell 查询**:
    
    PowerShell
    
    ```
    Get-WinEvent -Path <Path_to_Log> -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'
    ```
    

##### 追踪持久化

- **假设**: 攻击者通过在启动文件夹中放置文件或修改注册表 Run 键来实现持久化。
    
- **配置 (启动文件夹)**:
    
    XML
    
    ```
    <RuleGroup name="" groupRelation="or">
        <FileCreate onmatch="include">
            <TargetFilename name="T1547.001" condition="contains">\Start Menu</TargetFilename>
            <TargetFilename name="T1547.001" condition="contains">\Startup\</TargetFilename>
        </FileCreate>
    </RuleGroup>
    ```
    
- **配置 (Run 键)**:
    
    XML
    
    ```
    <RuleGroup name="" groupRelation="or">
        <RegistryEvent onmatch="include">
            <TargetObject name="T1547.001,RunKey" condition="contains">CurrentVersion\Run</TargetObject>
        </RegistryEvent>
    </RuleGroup>
    ```
    

##### 检测规避技术

- **假设**: 攻击者使用替代数据流 (ADS) 来隐藏文件，或使用远程线程注入来执行恶意代码。
    
- **配置 (ADS)**:
    
    XML
    
    ```
    <FileCreateStreamHash onmatch="include">
        <TargetFilename condition="contains">Downloads</TargetFilename>
        <TargetFilename condition="ends with">.hta</TargetFilename>
    </FileCreateStreamHash>
    ```
    
- **配置 (远程线程)**:
    
    XML
    
    ```
    <CreateRemoteThread onmatch="exclude">
        <SourceImage condition="is">C:\Windows\system32\svchost.exe</SourceImage>
    </CreateRemoteThread>
    ```
    
- **PowerShell 查询 (远程线程)**:
    
    PowerShell
    
    ```
    Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=8'
    ```