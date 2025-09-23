#### 概述：什么是 Windows 事件日志？ (Overview: What are Windows Event Logs?)

根据维基百科，“事件日志记录系统执行过程中发生的事件，以提供可用于理解系统活动并诊断问题的审计追踪。” 对于系统管理员来说，它们是排查故障的关键工具。

对于安全防御者而言，事件日志扮演着更重要的角色。通过聚合来自多个端点的日志并进行分析，可以发现看似无关事件之间的关联，从而识别复杂的攻击活动。这正是 **SIEM (安全信息和事件管理)** 系统（如 Splunk, Elastic）的核心价值。

##### 事件日志的分类 (Categories of Event Logs)

- **系统日志 (System)**: 记录操作系统组件相关的事件，如硬件变更、设备驱动程序问题等。
    
- **安全日志 (Security)**: **分析师最重要的日志之一**。记录登录/注销活动、权限变更等安全审计事件。
    
- **应用程序日志 (Application)**: 记录系统上安装的应用程序相关的事件，如应用程序错误、警告等。
    
- **目录服务日志 (Directory Service)**: 记录 Active Directory 相关的变更和活动（主要在域控制器上）。
    
- **DNS 事件日志 (DNS Server)**: 记录 DNS 服务器处理的域名事件。
    
- **自定义日志 (Custom Logs)**: 由特定应用程序创建，用于记录其自身的事件。
    

##### 事件日志的格式 (Format of Event Logs)

Windows 事件日志不是纯文本文件，而是以专有的二进制格式存储，扩展名为 `.evt` (旧版) 或 `.evtx` (现代)。

- **默认存储位置**: `C:\Windows\System32\winevt\Logs\`
    

#### 1. 访问方法：事件查看器 (GUI) (Access Method 1: Event Viewer)

事件查看器 (`eventvwr.msc`) 是 Windows 内置的图形化日志分析工具。

##### 界面导览 (Interface Navigation)

- **左侧窗格**: 以树状结构显示所有可用的日志提供程序。核心日志位于 **“Windows 日志”** 下，特定应用的日志（如 PowerShell）位于 **“应用程序和服务日志”** 下。
    
- **中间窗格**: 显示所选日志提供程序的所有事件列表。
    
- **右侧窗格 (操作)**: 提供针对当前日志或事件可执行的操作。
    

##### 日志属性与轮转 (Log Properties and Rotation)

右键单击任何日志并选择“属性”，可以查看和配置：

- 日志文件的物理位置和大小。
    
- **日志轮转 (Log Rotation)**: 设置当日志文件达到最大尺寸时的操作（例如，覆盖最旧的事件）。
    
- **清除日志 (Clear Log)**: 攻击者可能会执行此操作以擦除痕迹。
    

##### 事件详情 (Event Details)

- **事件列表列**:
    
    - **级别 (Level)**: 事件的严重性（如信息、警告、错误）。
        
    - **源 (Source)**: 记录该事件的软件或组件。
        
    - **事件 ID (Event ID)**: 映射到特定操作的数字代码，**是筛选和识别事件的核心**。
        
    - **任务类别 (Task Category)**: 事件的分类。
        
- **详情窗格**:
    
    - **常规 (General)**: 以易于阅读的格式显示事件信息。
        
    - **详细信息 (Details)**:
        
        - **友好视图 (Friendly View)**: 结构化的文本视图。
            
        - **XML 视图 (XML View)**: **构建高级查询的基础**，显示事件的原始 XML 数据。
            

#### 2. 访问方法：wevtutil.exe (命令行) (Access Method 2: wevtutil.exe)

`wevtutil.exe` 是一个强大的原生命令行工具，用于查询、导出、归档和清除事件日志。

- **获取帮助**:
    
    Code snippet
    
    ```
    :: 查看所有可用命令
    wevtutil.exe /?
    
    :: 查看特定命令的帮助 (例如 qe - query-events)
    wevtutil qe /?
    ```
    

#### 3. 访问方法：Get-WinEvent (PowerShell) (Access Method 3: Get-WinEvent)

`Get-WinEvent` 是 PowerShell 中用于处理事件日志的核心 cmdlet，它取代了旧的 `Get-EventLog` 命令，并提供了更强大的筛选功能。

##### 基本用法 (Basic Usage)

- **示例 1：列出所有日志**:
    
    PowerShell
    
    ```
    Get-WinEvent -ListLog *
    ```
    
- **示例 2：列出所有提供程序**:
    
    PowerShell
    
    ```
    Get-WinEvent -ListProvider *
    ```
    

##### 日志筛选 (Log Filtering)

###### 方法一：使用 `Where-Object` (低效)

虽然可行，但在处理大型日志时，此方法效率低下，因为它会先获取所有日志，然后再进行筛选。

PowerShell

```
Get-WinEvent -LogName Application | Where-Object { $_.ProviderName -Match 'WLMS' }
```

###### 方法二：使用 `FilterHashtable` (高效)

这是微软**推荐**的筛选方法，因为它在获取数据之前就应用了过滤器，效率极高。

- **语法**: 哈希表由一个或多个键值对构成，格式为 `@{ <Key> = <Value>; <Key> = <Value> }`。
    
- **示例**:
    
    PowerShell
    
    ```
    Get-WinEvent -FilterHashtable @{
      LogName='Application';
      ProviderName='WLMS'
    }
    ```
    

#### 4. 高级筛选：XPath 查询 (Advanced Filtering: XPath Queries)

XPath (XML Path Language) 是一种用于在 XML 文档中定位和筛选信息的语言。由于事件日志的底层是 XML 格式，因此可以使用 XPath 来构建极其精确和复杂的查询。

##### 使用事件查看器构建 XPath 查询

构建 XPath 查询最简单的方法是利用**事件查看器**的 **XML 视图**。

1. 在事件查看器中找到一个你感兴趣的事件。
    
2. 切换到“详细信息”标签页，并选择“XML 视图”。
    
3. XML 的结构直接对应于 XPath 的路径。
    

##### XPath 查询语法与示例

- **按事件 ID 查询**: XML 路径为 `Event/System/EventID`。
    
    - **PowerShell**:
        
        PowerShell
        
        ```
        Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=100'
        ```
        
    - **wevtutil.exe**:
        
        Code snippet
        
        ```
        wevtutil.exe qe Application /q:*/System[EventID=100] /f:text /c:1
        ```
        
- **按属性查询 (如提供程序名称)**: XML 路径为 `Event/System/Provider`，其属性为 `Name`。
    
    - **PowerShell**:
        
        PowerShell
        
        ```
        Get-WinEvent -LogName Application -FilterXPath '*/System/Provider[@Name="WLMS"]'
        ```
        
- **组合查询 (使用 `and`)**:
    
    - **PowerShell**:
        
        PowerShell
        
        ```
        Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=101 and */System/Provider[@Name="WLMS"]'
        ```
        
- **查询 `EventData` 中的数据**: 查询 `EventData` 部分的语法略有不同，需要指定 `Data` 元素的 `Name` 属性。
    
    - **示例**: 在安全日志中查找 `TargetUserName` 为 `System` 的事件。
        
    - **PowerShell**:
        
        PowerShell
        
        ```
        Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="System"' -MaxEvents 1
        ```