#### 概述 (Overview)

计算机取证是网络安全领域的核心分支，专注于收集和分析计算机活动证据。作为广义数字取证的一部分，它涵盖了对各类数字设备（包括计算机）中数据的恢复、检查与分析。其应用范围广泛，从在法律程序（民事或刑事）中支持或反驳某种假设，到在企业内部协助调查和安全事件响应。

数字取证在刑事侦破中的一个经典案例是 **BTK 连环杀手案**。该案件曾沉寂十余年，直到凶手开始向警方和媒体发送信件进行挑衅。当他寄送一张软盘到当地新闻机构后，案件迎来重大突破。警方成功恢复了软盘上一份被删除的 Word 文档，并通过其元数据及其他线索，最终锁定了凶手的身份并将其逮捕。

微软 Windows 是目前市场份额最高（约 80%）的桌面操作系统，被个人和企业广泛使用。因此，对于任何数字取证从业者而言，精通 Windows 系统的取证分析至关重要。

#### Windows 取证基础 (Windows Forensics Fundamentals)

##### 1. 取证证据 (Forensic Artifacts)

在取证分析中，“证据”（Artifacts）是指能够证明人类活动的、具有重要价值的信息片段。在物理犯罪现场，指纹、衣物纤维或犯罪工具等都被视为物证，它们共同构成了犯罪过程的全貌。

在计算机取证中，证据是用户活动在系统中留下的微小痕迹。Windows 系统会为特定活动创建并记录大量证据，使得调查人员能够通过取证技术相当精确地追溯个人行为。这些证据通常存储在普通用户不易接触的位置。

尽管开箱即用的 Windows 系统体验相似，但随着时间推移，每个用户都会根据个人偏好进行个性化设置，例如：

- 桌面布局和图标
    
- 网页浏览器书签
    
- 用户名和已安装的应用程序
    
- 登录各种网络服务的账户
    

Windows 保存这些偏好是为了提升用户体验，但对于取证调查员而言，这些偏好本身就是识别系统活动的关键证据。因此，系统记录用户信息并非为了明确的“监视”，而是为了个性化服务，但同样的信息却能被调查员用于专业的取证分析。

##### 2. Windows 注册表与取证 (Windows Registry and Forensics)

Windows 注册表是一个包含系统配置数据的核心数据库集合。这些数据涉及硬件、软件、用户信息，以及最近使用的文件、运行的程序或连接到系统的设备记录。

- **查看工具**: 可以使用 Windows 内置的 `regedit.exe` 工具来查看和编辑注册表。
    

注册表由 **键 (Keys)** 和 **值 (Values)** 组成。在 `regedit.exe` 中，文件夹结构是注册表键，而存储在键中的数据则是注册表值。一组相关的键、子键和值构成一个 **注册表数据库 (Registry Hive)**，它们存储在磁盘上的单个文件中。

#### Windows 注册表深度解析 (In-depth Windows Registry Analysis)

##### 1. 注册表结构 (Registry Structure)

任何 Windows 系统的注册表都包含以下五个根键 (Root Keys)：

- **HKEY_CURRENT_USER (HKCU)**: 包含当前登录用户的配置信息，如用户文件夹、屏幕颜色和控制面板设置。此信息与用户的配置文件相关联。
    
- **HKEY_USERS (HKU)**: 包含计算机上所有活动加载的用户配置文件。`HKEY_CURRENT_USER` 是 `HKEY_USERS` 的一个子键。
    
- **HKEY_LOCAL_MACHINE (HKLM)**: 包含特定于计算机的配置信息，适用于所有用户。
    
- **HKEY_CLASSES_ROOT (HKCR)**: 是 `HKEY_LOCAL_MACHINE\Software` 的一个子键，确保在使用 Windows 资源管理器打开文件时，系统能调用正确的程序。它合并了 `HKLM\Software\Classes` (默认设置) 和 `HKCU\Software\Classes` (用户特定设置) 的信息。
    
- **HKEY_CURRENT_CONFIG**: 包含系统启动时使用的硬件配置文件的信息。
    

##### 2. 访问注册表 Hive (Accessing Registry Hives)

在对活动系统进行分析时，可以直接使用 `regedit.exe`。但如果处理的是磁盘镜像，则必须知道注册表 Hive 文件在磁盘上的物理位置。

**系统级 Hive (大部分位于 `C:\Windows\System32\Config`)**:

1. `DEFAULT` (挂载于 `HKEY_USERS\DEFAULT`)
    
2. `SAM` (挂载于 `HKEY_LOCAL_MACHINE\SAM`)
    
3. `SECURITY` (挂载于 `HKEY_LOCAL_MACHINE\Security`)
    
4. `SOFTWARE` (挂载于 `HKEY_LOCAL_MACHINE\Software`)
    
5. `SYSTEM` (挂载于 `HKEY_LOCAL_MACHINE\System`)
    

**用户级 Hive (位于用户配置文件目录 `C:\Users\<username>\`)**:

1. `NTUSER.DAT` (用户登录时挂载于 `HKEY_CURRENT_USER`)
    
2. `USRCLASS.DAT` (位于 `AppData\Local\Microsoft\Windows\`，挂载于 `HKEY_CURRENT_USER\Software\CLASSES`)
    

**其他重要 Hive**:

- `Amcache.hve` (位于 `C:\Windows\AppCompat\Programs\`)：记录系统上最近运行程序的详细信息。
    

##### 3. 事务日志和备份 (Transaction Logs and Backups)

- **事务日志 (`.LOG` 文件)**: 这是注册表键的变更日志。Windows 在向注册表写入数据时会使用它，因此日志文件通常包含比注册表 Hive 本身更新的变更。每个 Hive 的日志文件与其位于同一目录，例如 `SAM.LOG`。
    
- **注册表备份**: Windows 会定期（约每十天）将 `C:\Windows\System32\Config` 目录中的注册表 Hive 备份到 `C:\Windows\System32\Config\RegBack` 目录。如果怀疑最近有键被删除或修改，这里是重要的调查来源。
    

#### 取证流程与工具 (Forensics Process and Tools)

##### 1. 数据获取 (Data Acquisition)

正确的取证方法是先制作系统镜像或复制所需数据副本，再进行分析，以确保原始证据的完整性。由于系统级注册表 Hive 是受保护文件，无法直接复制，因此需要使用专业工具获取。

**常用获取工具**:

- **[[KAPE]]**: 一款实时数据采集和分析工具，支持命令行和图形界面，可用于获取注册表数据。
    
- **[[Autopsy]]**: 可以从活动系统或磁盘镜像中提取数据。通过导航到文件位置并选择“提取文件”即可。
    
- **FTK Imager**: 功能与 Autopsy 类似，可以挂载磁盘镜像或活动驱动器以提取文件。其“获取受保护文件”功能可提取所有注册表 Hive（但不包括 `Amcache.hve`）。
    

##### 2. 注册表分析工具 (Registry Analysis Tools)

提取注册表 Hive 后，需要使用专用工具进行离线分析。

**常用分析工具**:

- **Registry Viewer (AccessData)**: 界面类似于 `regedit.exe`，但一次只能加载一个 Hive，且不支持事务日志。
    
- **Registry Explorer (Eric Zimmerman)**: 功能强大，可以同时加载多个 Hive，并能自动合并事务日志中的数据，提供更完整、更新的视图。内置“书签”功能，可快速跳转到重要的取证键值。
    
- **RegRipper**: 以注册表 Hive 为输入，生成一份包含其中重要取证键值信息的文本报告。但它不处理事务日志，建议先用 Registry Explorer 合并日志后再使用。
    

#### 从注册表中提取的关键信息 (Key Information from the Registry)

##### 1. 系统信息和账户 (System Information and Accounts)

- **操作系统版本**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
    
- **当前控制集 (Current Control Set)**: 控制系统启动的配置数据。通过 `SYSTEM\Select\Current` 的值确定当前使用的是 `ControlSet001` 还是 `ControlSet002`。分析时应参考 `SYSTEM\CurrentControlSet`。
    
- **计算机名**: `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`
    
- **时区信息**: `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`
    
- **网络接口和历史网络**:
    
    - 接口信息 (IP, DHCP, DNS): `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`
        
    - 历史连接网络: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged`
        
- 自动启动程序与持久化:
    
    恶意软件为了在系统重启后依然能够运行，常通过修改注册表中的自启动项来实现持久化。手动检查这些位置是发现恶意软件的重要一步。
    
    - **常见自启动注册表键**:
        
        - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` (当前用户登录时运行)
            
        - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` (任何用户登录时运行)
            
        - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce` (当前用户登录时运行一次，然后删除)
            
        - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce` (任何用户登录时运行一次，然后删除)
            
        - 以及 `policies\Explorer\Run` 等其他键。
            
    - **服务**: `SYSTEM\CurrentControlSet\Services` (start 值为 `0x02` 的服务会在启动时运行)。
        
    - 使用 AutoRuns 进行自动化检测:
        
        手动检查所有可能的自启动位置非常繁琐且容易遗漏。微软官方工具 AutoRuns (及其 PowerShell 模块) 可以自动检查所有已知的自启动位置（包括注册表、计划任务、服务等）。
        
        - **初步分析**: `Get-PSAutorun` 命令会列出所有自启动项。建议将其输出通过管道传递给 `Out-GridView` 以便交互式地过滤和排序。
            
            PowerShell
            
            ```
            Get-PSAutorun | Out-GridView
            ```
            
        - **基线比较**: 这是 AutoRuns 最强大的功能。你可以先在干净的系统上创建一个“基线”快照，然后在系统疑似被感染后，创建另一个快照并进行比较，从而快速找出新增或被修改的自启动项。
            
            1. **创建基线**:
                
                PowerShell
                
                ```
                Get-PSAutorun -VerifyDigitalSignature |
                >> Where { -not($_.isOSbinary)} |
                >> New-AutoRunsBaseLine -Verbose
                ```
                
            2. **比较基线**:
                
                PowerShell
                
                ```
                Compare-AutoRunsBaseLine -Verbose | Out-GridView
                ```
                
- **SAM Hive 和用户信息**:
    
    - `SAM\Domains\Account\Users`: 包含用户 RID、登录次数、最后一次登录时间、密码策略等信息。
        

##### 2. 文件/文件夹使用痕迹 (File/Folder Usage and Knowledge)

- **最近打开的文件 (Recent Files)**:
    
    - `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: 包含按文件扩展名分类的最近使用文件列表和最后打开时间。
        
- **Office 最近文件**:
    
    - `NTUSER.DAT\Software\Microsoft\Office\VERSION\UserMRU\LiveID_####\FileMRU`: 记录 Microsoft Office 程序最近打开的文档。
        
- **ShellBags**: 记录用户在 Windows 资源管理器中查看文件夹的偏好（如视图、大小）。这些信息可用于识别用户访问过的文件夹。
    
    - `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
        
    - `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`
        
- **打开/保存对话框的最近使用项 (MRUs)**:
    
    - `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
        
- **Windows Explorer 地址/搜索栏历史**:
    
    - `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`
        
    - `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`
        

##### 3. 程序执行证据 (Execution Evidence)

- **UserAssist**: 记录用户通过 Windows Explorer 启动的 GUI 程序的执行次数和最后执行时间（不记录命令行程序）。
    
    - `NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count`
        
- **ShimCache (AppCompatCache)**: 用于确保应用程序向后兼容性的机制，记录了已启动程序的文件名、大小和最后修改时间。
    
    - `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
        
- **AmCache**: 类似于 ShimCache，但存储更丰富的数据，包括执行路径、安装时间、SHA1 哈希值等。
    
    - `Amcache.hve\Root\File\{Volume GUID}\`
        
- **BAM/DAM**: 背景活动监视器 (BAM) 和桌面活动调节器 (DAM) 记录了应用程序的完整路径及其最后执行时间。
    
    - `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`
        
    - `SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}`
        

##### 4. 外部设备/USB设备取证 (External/USB Device Forensics)

- **设备识别**: 记录了插入系统的 USB 设备的供应商 ID、产品 ID 和版本，以及首次插入时间。
    
    - `SYSTEM\CurrentControlSet\Enum\USBSTOR`
        
    - `SYSTEM\CurrentControlSet\Enum\USB`
        
- **首次/最后插入时间**: 记录设备首次连接、最后一次连接及最后一次移除的时间。
    
    - `SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####`
        
    - `0064`: 首次连接时间
        
    - `0066`: 最后一次连接时间
        
    - `0067`: 最后一次移除时间
        
- **USB 设备卷名**:
    
    - `SOFTWARE\Microsoft\Windows Portable Devices\Devices`: 可通过 GUID 与设备 ID 关联，确定设备名称。
        

#### 文件系统取证 (File System Forensics)

文件系统负责组织存储设备上的比特流，使其成为可读信息。

##### 1. 文件分配表 (File Allocation Table, FAT)

FAT 是一种历史悠久的文件系统，通过索引来标记文件在磁盘上的位置。

- **核心数据结构**:
    
    - **簇 (Cluster)**: 基本存储单元。
        
    - **目录 (Directory)**: 包含文件名、起始簇和文件长度等元信息。
        
    - **文件分配表 (File Allocation Table)**: 包含所有簇状态的链表，指向文件的下一个簇。
        
- **版本**:
    
    - **FAT12, FAT16, FAT32**: 使用不同位数进行簇寻址，决定了最大卷和文件大小。FAT32 最大支持 2TB 卷和 4GB 文件，常用于 U 盘和 SD 卡。
        
    - **exFAT**: 为解决 FAT32 的 4GB 文件大小限制而设计，适用于大容量 SD 卡和数码设备，支持高达 128PB 的文件和卷。
        

|**特性**|**FAT12**|**FAT16**|**FAT32**|
|---|---|---|---|
|**可寻址位数**|12|16|28|
|**最大簇数**|4,096|65,536|268,435,456|
|**最大卷大小**|32MB|2GB|2TB|

##### 2. 新技术文件系统 (New Technology File System, NTFS)

NTFS 是现代 Windows 系统的默认文件系统，相较于 FAT 提供了更强的功能。

- **主要特性**:
    
    - **日志记录**: 将元数据变更记录在 `$LOGFILE` 中，提高了系统崩溃后的恢复能力。
        
    - **访问控制**: 支持基于用户的文件/目录权限设置。
        
    - **卷影副本 (Volume Shadow Copy)**: 跟踪文件变更，支持文件版本恢复和系统还原。
        
    - **替代数据流 (Alternate Data Streams, ADS)**: 允许单个文件包含多个数据流，常被浏览器用于标记下载文件，也可能被恶意软件滥用。
        
- **主文件表 (Master File Table, MFT)**: NTFS 的核心，是一个结构化数据库，跟踪卷中所有对象。
    
    - **`$MFT`**: 卷的第一个记录，包含卷上所有文件的目录。
        
    - **`$LOGFILE`**: 存储文件系统的事务日志。
        
    - **`$UsnJrnl`**: 更新序列号 (USN) 日志，记录文件系统中所有文件的变更及其原因。
        

#### 常见取证分析任务 (Common Forensic Analysis Tasks)

##### 1. 恢复删除的文件 (Recovering Deleted Files)

删除文件时，文件系统仅删除指向文件磁盘位置的条目，并将该空间标记为“未分配”。只要实际数据未被新文件覆盖，就有可能恢复。**Autopsy** 等工具可以通过扫描磁盘镜像的未分配空间来恢复已删除的文件。

##### 2. 分析程序执行证据 (Analyzing Execution Evidence)

- **Windows Prefetch 文件 (`.pf`)**:
    
    - **位置**: `C:\Windows\Prefetch\`
        
    - **信息**: 包含应用程序的最后运行时间、运行次数以及所用文件和设备的句柄。是分析程序执行历史的重要来源。
        
    - **工具**: `PECmd.exe` (Eric Zimmerman)
        
- **Windows 10 时间线 (Timeline)**:
    
    - **位置**: `C:\Users\<username>\AppData\Local\ConnectedDevicesPlatform\{...}\ActivitiesCache.db`
        
    - **信息**: 一个 SQLite 数据库，存储最近使用的应用程序和文件，以及应用的专注时间。
        
    - **工具**: `WxTCmd.exe` (Eric Zimmerman)
        
- **Windows 跳转列表 (Jump Lists)**:
    
    - **位置**: `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`
        
    - **信息**: 存储用户从任务栏访问的最近使用的文件，包含应用程序的首次和最后执行时间。
        
    - **工具**: `JLECmd.exe` (Eric Zimmerman)
        

##### 3. 分析文件/文件夹访问痕迹 (Analyzing File/Folder Access Traces)

- **快捷方式文件 (`.lnk`)**:
    
    - **位置**: `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\`
        
    - **信息**: Windows 为每个打开的文件创建的快捷方式，包含文件首次打开时间（创建日期）和最后打开时间（修改日期），以及原始路径。
        
    - **工具**: `LECmd.exe` (Eric Zimmerman)
        
- **IE/Edge 历史记录**:
    
    - **位置**: `C:\Users\<username>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat`
        
    - **信息**: 不仅记录网页浏览历史，也记录通过系统打开的本地文件（以 `file:///*` 前缀标识）。
        
- **跳转列表 (Jump Lists)**: 如上所述，跳转列表也是识别最近打开文件的重要证据来源。
    

##### 4. 分析外部设备使用痕迹 (Analyzing External Device Usage)

- **Setupapi.dev 日志**:
    
    - **位置**: `C:\Windows\inf\setupapi.dev.log`
        
    - **信息**: 记录任何新设备连接到系统时的设置信息，包含设备序列号以及首次和最后一次连接的时间。
        
- **快捷方式文件 (`.lnk`)**: 如上所述，当用户从 USB 设备打开文件时，系统会创建快捷方式文件。这些文件可以揭示该 USB 设备的卷名、类型和序列号。