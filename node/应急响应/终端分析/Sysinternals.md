#### 概述 (Overview)

**Sysinternals 工具**是一个由微软官方提供的、包含超过 70 个强大的 Windows 工具的集合。这些工具为系统管理员、开发人员和 IT 安全专业人员提供了深入洞察、管理和排查 Windows 操作系统问题的能力。

每个工具都属于以下类别之一：

- 文件和磁盘工具 (File and Disk Utilities)
    
- 网络工具 (Networking Utilities)
    
- 进程工具 (Process Utilities)
    
- 安全工具 (Security Utilities)
    
- 系统信息 (System Information)
    
- 杂项 (Miscellaneous)
    

#### 1. 安装 Sysinternals 套件 (Installing the Sysinternals Suite)

##### 方法一：下载单个工具

访问 [Sysinternals 工具索引页面](https://docs.microsoft.com/en-us/sysinternals/downloads/)，可以按字母顺序查找并下载所需的单个工具。

##### 方法二：下载完整套件

从 [Sysinternals Suite 下载页面](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) 下载包含所有工具的 zip 压缩包。解压后，建议将文件夹路径添加到系统的环境变量中，这样就可以在任何位置通过命令行直接启动工具。

##### 方法三：使用 PowerShell 模块

可以使用 PowerShell 命令一键下载并安装所有 Sysinternals 工具到指定目录。

PowerShell

```
Download-SysInternalsTools C:\Tools\Sysint
```

#### 2. 使用 Sysinternals Live

**Sysinternals Live** 是一项服务，允许你直接从网络运行 Sysinternals 工具，而无需下载。

- **访问语法**:
    
    - `live.sysinternals.com/<工具名>`
        
    - `\\live.sysinternals.com\tools\<工具名>`
        

##### 先决条件 (Prerequisites)

- **WebClient 服务**: 必须确保 `WebClient` 服务（WebDAV 客户端）正在运行。
    
    PowerShell
    
    ```
    Get-Service WebClient
    Start-Service WebClient
    ```
    
- **网络发现 (Network Discovery)**: 必须启用此功能。
    
    - 可以通过 `control.exe /name Microsoft.NetworkAndSharingCenter` 打开网络和共享中心，在高级共享设置中启用。
        
- **Windows Server 的额外要求**:
    
    - 需要安装 **WebDAV 重定向器 (WebDAV-Redirector)** 功能。
        
        PowerShell
        
        ```
        Install-WindowsFeature WebDAV-Redirector –Restart
        ```
        

##### 运行方法 (Methods of Execution)

1. **从命令行运行**:
    
    Code snippet
    
    ```
    \\live.sysinternals.com\tools\procmon.exe
    ```
    
2. **从映射的网络驱动器运行**:
    
    Code snippet
    
    ```
    :: 星号(*)会自动分配一个可用的驱动器号
    net use * \\live.sysinternals.com\tools\
    ```
    

#### 3. 工具详解 (Tool Spotlights)

##### 文件和磁盘工具 (File and Disk Utilities)

- **Sigcheck**: 一个命令行工具，用于显示文件的版本、时间戳和数字签名详情。它还可以检查文件在 VirusTotal 上的状态。
    
    - **用例**: 检查 `System32` 目录中所有未签名的可执行文件。
        
        Code snippet
        
        ```
        sigcheck -u -e C:\Windows\System32
        ```
        
- **Streams**: 用于查看 NTFS 文件系统中的**替代数据流 (Alternate Data Streams, ADS)**。ADS 是一种文件属性，允许一个文件包含多个数据流，常被浏览器用于标记从互联网下载的文件，也曾被恶意软件用于隐藏数据。
    
- **SDelete**: 一款实现了国防部清除和清理协议 (DOD 5220.22-M) 的安全删除工具。它被攻击者用于数据销毁 (MITRE T1485) 和清除主机上的指标 (MITRE T1070.004)。
    

##### 网络工具 (Networking Utilities)

- **TCPView**: 一个图形界面程序，实时显示系统上所有 TCP 和 UDP 连接的详细列表，包括本地/远程地址、状态和所属进程。它比 Windows 自带的 `netstat` 工具更直观、信息更丰富。
    
    > **内置替代品**: Windows 自带的**资源监视器 (`resmon`)** 提供了类似的网络连接监控功能。
    

##### 进程工具 (Process Utilities)

- **Autoruns**: **最全面**的启动项监视器。它能显示系统启动或用户登录时自动运行的所有程序、驱动、服务、DLL 等，是排查恶意软件**持久化**的必备工具。
    
- **ProcDump**: 一款命令行工具，主要用于在应用程序 CPU 占用率飙升时生成其内存转储 (dump) 文件，以便进行故障排查。
    
- **Process Explorer**: 强大的任务管理器替代品。它以树状结构显示进程关系，并能查看每个进程打开的句柄 (handles) 和加载的 DLL。
    
- **Process Monitor**: 一款高级监控工具，实时显示文件系统、注册表和进程/线程的**所有活动**。是排查系统问题和分析恶意软件行为的核心工具。
    
- **PsExec**: 一个轻量级的 telnet 替代品，允许在远程系统上执行命令。常被攻击者用于横向移动 (MITRE T1570, T1021.002)。
    

##### 安全工具 (Security Utilities)

- **Sysmon**: 系统监视器。它作为一个系统服务和设备驱动程序安装在系统上，能够监控并记录极为详细的系统活动（如进程创建、网络连接、文件创建时间变更等）到 Windows 事件日志中，是进行深度威胁狩 HUNTING 和应急响应的基石。
    

##### 系统信息 (System Information)

- **WinObj**: 用于查看 Windows NT 对象管理器 (Object Manager) 的命名空间。可以清晰地看到操作系统会话 (Session 0) 和用户会话 (Session 1) 的隔离。
    

##### 杂项 (Miscellaneous)

- **BgInfo**: 自动在桌面背景上显示计算机的详细信息，如主机名、IP 地址、系统版本等，非常便于管理多台机器。
    
- **RegJump**: 一个命令行小程序，可以快速打开注册表编辑器 (`Regedit`) 并直接跳转到指定的路径。
    
    Code snippet
    
    ```
    regjump HKLM\Software\Microsoft\Windows
    ```
    
- **Strings**: 经典工具，用于扫描文件并提取其中所有可读的 UNICODE 或 ASCII 字符串。