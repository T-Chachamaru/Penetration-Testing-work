#### 概述：什么是 Velociraptor？ (Overview: What is Velociraptor?)

**Velociraptor** 是一款功能强大的开源数字取证与应急响应 (DFIR) 平台。其独特之处在于，单个可执行文件既能充当**服务器 (Server)** 也能充当**客户端 (Client)**，并且跨平台兼容 Windows, Linux 和 macOS。Velociraptor 可以轻松部署在数千个端点上，并能与云文件系统（如 Amazon EFS）集成。

- **启动 (Windows)**:
    
    ```
    velociraptor.exe gui
    ```
    

#### 1. 客户端管理 (Client Management)

##### 与客户端交互 (Interacting with a Client)

首次登录 Velociraptor Web 界面时，许多针对客户端的链接是灰色的，直到有客户端连接并被选中后才会激活。

- **添加客户端**: 在客户端机器上运行预配置的客户端安装命令。
    
- **查看客户端**: 在 Velociraptor UI 的搜索栏中，直接点击**放大镜图标**或点击 **`Show All`** 按钮，即可查看所有已连接的客户端。
    

##### 客户端列表详解 (Understanding the Client List)

|列名|描述|
|---|---|
|**在线状态 (Online Status)**|`●` 绿色表示在线；`●` 黄色表示 24 小时内未通信；`●` 红色表示超过 24 小时未通信。|
|**客户端ID (Client ID)**|服务器分配给客户端的唯一 ID（以 `C` 开头），是识别端点的核心标识。|
|**主机名 (Hostname)**|客户端的主机名。由于主机名可变，Velociraptor 依赖客户端 ID 进行唯一识别。|
|**操作系统版本 (OS Version)**|显示客户端的操作系统及版本。|
|**标签 (Labels)**|用于对客户端进行分组，便于批量管理和操作。|

##### 客户端详细视图 (Client Deep Dive)

点击任意一个客户端 ID，即可进入该客户端的详细视图。

- **概述 (Overview)**: 显示客户端的基本信息，如代理版本、最后上线时间、IP 地址、操作系统、硬件架构等。
    
- **VQL Drilldown**: 提供更深入的客户端信息，包括过去 24 小时的**内存 (橙色)**和 **CPU (蓝色)** 使用情况图表，以及本地账户信息。
    
- **Shell**: **远程命令执行接口**。允许分析师在客户端上远程运行 `PowerShell`、`CMD`、`Bash` 或 `VQL` 命令。
    
- **已收集 (Collected)**: 查看所有在该客户端上已完成的**收集任务 (Flows)** 的结果。顶部窗格是任务列表，点击任意任务 ID (FlowId) 可以在底部窗格查看其详细结果。
    
- **审问 (Interrogation)**: “审问”是一个标准操作，用于查询并收集主机的基本信息。执行此操作后，结果会出现在“已收集”标签页中，对应的工件为 `Generic.Client.Info`。
    

#### 2. 收集证据 (Collecting Artifacts)

Velociraptor 通过“工件 (Artifacts)”来收集证据。创建一个新的收集任务通常遵循以下流程。

##### 创建新集合：五步流程 (Creating a New Collection: The 5-Step Process)

1. **选择工件 (Select Artifacts)**:
    
    - 在搜索栏中输入并选择你想要运行的工件。例如，输入 `Windows.KapeFiles.Targets`，这是一个用于收集 KAPE 兼容证据的社区工件。
        
2. **配置参数 (Configure Parameters)**:
    
    - 根据工件的描述，配置其运行参数。例如，在 `Windows.KapeFiles.Targets` 中，你可以勾选你想要收集的目标（如 `Ubuntu` WLS 文件）。
        
3. **指定资源 (Specify Resources)**:
    
    - 配置收集任务的资源限制，如 CPU 和网络带宽。通常可以保持默认设置。
        
4. **审核 (Review)**:
    
    - 以 JSON 格式预览即将下发的收集任务配置，确保所有参数都已正确设置。
        
5. **启动 (Launch)**:
    
    - 点击启动按钮，任务将被下发到客户端。你会被重定向到该客户端的“已收集”视图，并能看到新任务的状态（沙漏图标表示正在运行）。
        

#### 3. 核心功能 (Core Features)

##### VFS (虚拟文件系统 - Virtual File System)

**VFS** 是 Velociraptor 提供的一个强大接口，允许分析师**交互式地浏览客户端的文件系统**，并在必要时下载文件，而无需启动完整的收集任务。

- **访问器 (Accessors)**: VFS 通过不同的“访问器”来访问数据：
    
    - `file`: 使用操作系统 API 访问标准文件系统。
        
    - `ntfs`: 使用原始 NTFS 解析器访问低级文件结构。
        
    - `registry`: 使用操作系统 API 访问 Windows 注册表。
        
    - `artifacts`: 浏览之前运行过的收集任务的结果。
        
- **UI 按钮**:
    
    1. **刷新当前目录**: 同步当前目录的文件列表。
        
    2. **递归刷新此目录**: 递归同步当前目录及其所有子目录。
        
    3. **递归下载此目录**: 将整个目录从客户端下载到服务器。
        

##### VQL (Velociraptor 查询语言 - Velociraptor Query Language)

**VQL** 是 Velociraptor 的核心和灵魂。它是一种类似 SQL 的查询语言，用于创建高度定制化的工件，从而查询、监控和响应端点上的几乎任何情况。

- **Notebooks：编写和运行 VQL**:
    
    - Notebooks 是 Velociraptor 中用于编写和执行自定义 VQL 查询的交互式环境，类似于 Jupyter Notebook。
        
    - 你可以在 Notebook 中混合使用 Markdown（用于记录）和 VQL（用于查询）。
        
    - **示例**: 查询客户端基本信息。
        
        SQL
        
        ```
        SELECT * FROM info()
        ```
        
- **Artifacts：打包的 VQL 查询**:
    
    - **工件 (Artifacts)** 本质上是包含 VQL 查询的结构化 YAML 文件。它们将复杂的 VQL 查询打包成易于搜索和使用的“迷你程序”，使分析师无需深入了解 VQL 语法也能运行强大的查询。
        

##### Forensic VQL 插件 (Forensic VQL Plugins)

VQL 的强大功能来自于其丰富的插件生态系统，这些插件专为 DFIR 调查而设计。

- **法医分析相关插件类别**:
    
    - 搜索文件名 (Searching Filenames)
        
    - 搜索文件内容 (Searching Content)
        
    - NTFS 分析 (NTFS Analysis)
        
    - 二进制文件解析 (Binary Parsing)
        
    - 执行证据 (Evidence of Execution)
        
    - 事件日志 (Event Logs)
        
    - 易失性机器状态 (Volatile Machine State)