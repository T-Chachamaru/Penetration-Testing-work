#### 1. 安装 Volatility (Installing Volatility)

Volatility 框架完全使用 Python 编写，因此其安装过程在 Windows、Linux 和 Mac 操作系统上都相对简单。

##### 系统要求与依赖 (System Requirements & Dependencies)

- **必需依赖**:
    
    - [Python 3.5.3 或更高版本](https://www.python.org/)
        
    - [Pefile 2017.8.1 或更高版本](https://pypi.org/project/pefile/)
        
- **可选依赖 (用于增强功能)**:
    
    - [yara-python 3.8.0 或更高版本](https://github.com/VirusTotal/yara-python) (用于 YARA 扫描)
        
    - [capstone 3.0.0 或更高版本](https://www.capstone-engine.org/download.html) (用于反汇编)
        

##### 安装方法 (Installation Methods)

1. **预打包的可执行文件 (Windows)**:
    
    - 访问 Volatility 3 的 [发布页面](https://github.com/volatilityfoundation/volatility3/releases/tag/v1.0.1)。
        
    - 下载包含 `volatility3.exe` 的 zip 文件。这种方式无需安装任何依赖，开箱即用。
        
2. **从源代码运行 (所有系统)**:
    
    - 确保已安装上述必需依赖。
        
    - 使用 Git 克隆官方存储库：
        
        Bash
        
        ```
        git clone https://github.com/volatilityfoundation/volatility3.git
        ```
        
    - **测试安装**: 切换到 `volatility3` 目录，并使用帮助参数运行 `vol.py` 文件。
        
        Bash
        
        ```
        cd volatility3
        python3 vol.py --help
        ```
        

> **注意**：分析 Linux 或 Mac 的内存转储文件时，需要从 [Volatility GitHub](https://github.com/volatilityfoundation/volatility3#symbol-tables) 下载相应的符号表文件。

#### 2. 内存提取 (Memory Acquisition)

##### 物理机 (Bare Metal)

以下工具可用于从物理机中提取内存，通常会输出一个 `.raw` 格式的转储文件：

- FTK Imager
    
- Redline
    
- DumpIt.exe
    
- win32dd.exe / win64dd.exe
    
- Memoryze
    
- FastDump
    

##### 虚拟机 (Virtual Machines)

对于虚拟机，可以直接从宿主机的文件系统中复制其虚拟内存文件。

- **VMWare**: `.vmem` 文件
    
- **Hyper-V**: `.bin` 文件
    
- **Parallels**: `.mem` 文件
    
- **VirtualBox**: `.sav` 文件 (仅包含部分内存)
    

#### 3. Volatility 3 插件概述 (Plugin Overview in Volatility 3)

##### 从 Volatility 2 到 3 的主要变化

- **废除 OS 配置文件**: Volatility 3 不再需要像旧版本那样手动指定操作系统的配置文件（Profile）。它会自动检测内存转储文件的操作系统和构建版本，极大地简化了分析流程。
    
- **新的插件命名结构**: 插件名称现在必须以操作系统作为前缀，以区分不同系统的内存结构。
    
    - `.windows` (例如: `windows.info`)
        
    - `.linux` (例如: `linux.info`)
        
    - `.mac` (例如: `mac.info`)
        

#### 4. 基础分析：识别镜像与进程 (Basic Analysis: Identifying Image & Processes)

##### 识别镜像信息 (Identifying Image Information)

在 Volatility 2 中，`imageinfo` 插件用于猜测内存镜像的配置文件。在 Volatility 3 中，这一功能已被更精确的 `info` 插件取代。

- **命令**:
    
    Bash
    
    ```
    python3 vol.py -f <file> windows.info
    ```
    
- **功能**: 此插件会提供关于内存转储来源主机的详细信息，如操作系统版本、构建号、硬件架构等。
    

##### 列出进程 (Listing Processes)

- **`pslist`**:
    
    - **功能**: 列出所有当前和已终止的进程，类似于任务管理器。它通过遍历内存中跟踪进程的双向链表来实现。
        
    - **命令**:
        
        Bash
        
        ```
        python3 vol.py -f <file> windows.pslist
        ```
        
- **`psscan`**:
    
    - **功能**: 用于发现被 Rootkit 等恶意软件“摘链”隐藏的进程。它通过扫描整个内存来查找 `_EPROCESS` 结构，而不是依赖于进程链表。
        
    - **命令**:
        
        Bash
        
        ```
        python3 vol.py -f <file> windows.psscan
        ```
        
- **`pstree`**:
    
    - **功能**: 以树状结构显示所有进程及其父子关系，非常适合用于理解进程的派生关系和执行流程。
        
    - **命令**:
        
        Bash
        
        ```
        python3 vol.py -f <file> windows.pstree
        ```
        

##### 列出网络连接与 DLL (Listing Network Connections & DLLs)

- **`netstat`**:
    
    - **功能**: 尝试识别内存中所有的网络连接结构，显示活动的 TCP/UDP 连接。
        
    - **命令**:
        
        Bash
        
        ```
        python3 vol.py -f <file> windows.netstat
        ```
        
    
    > **注意**：此插件在某些旧版 Windows 系统上可能不稳定。如果无法获取结果，可以考虑使用 [bulk_extractor](https://tools.kali.org/forensics/bulk-extractor) 等工具直接从内存文件中提取 PCAP 文件。
    
- **`dlllist`**:
    
    - **功能**: 列出与特定进程或所有进程相关联的动态链接库（DLL）。这对于识别特定恶意软件加载的恶意 DLL 非常有用。
        
    - **命令**:
        
        Bash
        
        ```
        python3 vol.py -f <file> windows.dlllist
        ```
        

#### 5. 威胁狩猎与检测 (Threat Hunting and Detection)

##### 查找代码注入 (Finding Code Injection) - `malfind`

`malfind` 是狩猎代码注入最常用的插件之一。

- **工作原理**: 它通过扫描进程内存堆，查找同时具有读、写、执行（RWE 或 RX）权限且没有对应磁盘映射文件（即无文件恶意软件）的内存区域。
    
- **输出**: 识别出被注入的进程及其 PID，并提供受感染区域的十六进制、ASCII 和反汇编视图。输出中的 `MZ` 头通常表示一个完整的 Windows 可执行文件被注入。
    
- **命令**:
    
    Bash
    
    ```
    python3 vol.py -f <file> windows.malfind
    ```
    

##### YARA 扫描 (YARA Scanning) - `yarascan`

此插件允许你使用 YARA 规则在整个内存文件中搜索字符串、模式或复合规则。

- **命令**:
    
    Bash
    
    ```
    # 使用 YARA 规则文件
    python3 vol.py -f <file> windows.yarascan --yara-file /path/to/rules.yara
    
    # 直接在命令行中指定规则
    python3 vol.py -f <file> windows.yarascan --yara-rules "rule my_rule { strings: $a = \"evil_string\" condition: $a }"
    ```
    

#### 6. 高级内存取证 (Advanced Memory Forensics)

当面对使用高级规避技术的恶意软件（如 Rootkit）时，需要深入分析系统对象。

##### 追踪挂钩技术 (Tracking Hooking Techniques)

挂钩（Hooking）是恶意软件拦截和修改系统功能的常用技术。

- **五种主要挂钩方法**:
    
    - SSDT Hooks
        
    - IRP Hooks
        
    - IAT Hooks
        
    - EAT Hooks
        
    - Inline Hooks
        
- **`ssdt` 插件**:
    
    - **功能**: 专注于检测 **SSDT (系统服务描述表)** 挂钩。Windows 内核使用 SSDT 来定位系统函数，攻击者可以通过修改此表中的函数指针，将其指向恶意代码。
        
    - **命令**:
        
        Bash
        
        ```
        python3 vol.py -f <file> windows.ssdt
        ```
        
    
    > **注意**：合法应用程序也可能使用挂钩，因此分析师需要结合其他信息来判断结果是否为恶意。
    

##### 分析恶意驱动 (Analyzing Malicious Drivers)

- **`modules`**:
    
    - **功能**: 转储已加载的内核模块列表。有助于识别活跃的恶意软件驱动，但可能无法发现已卸载或隐藏的驱动。
        
    - **命令**:
        
        Bash
        
        ```
        python3 vol.py -f <file> windows.modules
        ```
        
- **`driverscan`**:
    
    - **功能**: 扫描内存中存在的驱动程序对象。此方法可以发现 `modules` 插件可能遗漏的隐藏驱动。
        
    - **命令**:
        
        Bash
        
        ```
        python3 vol.py -f <file> windows.driverscan
        ```
        

##### 其他高级插件 (Other Advanced Plugins)

以下插件有助于在内存中寻找高级恶意软件，其中一些仅在 Volatility 2 或作为第三方插件提供：

- `modscan`
    
- `driverirp`
    
- `callbacks`
    
- `idt`
    
- `apihooks`
    
- `moddump`
    
- `handles`