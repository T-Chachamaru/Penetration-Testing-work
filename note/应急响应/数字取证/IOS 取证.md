#### iOS 配对与访问控制 (iOS Pairing & Access Control)

##### 1. “限制模式”与信任证书 (Restriction Mode & Trust Certificates)

自 2018 年以来，Apple 在 iPhone 上强制实施了 **“限制模式” (Restriction Mode)**。此安全功能旨在防止恶意 USB 攻击和“充电窃取”，它会禁用设备的 USB 数据端口，除非设备已被解锁。

信任证书 (Trust Certificate)

当 iPhone 首次连接到一台新电脑时，系统会提示用户是否“信任”该设备。这是一个关键的安全机制，用于授权数据同步。

- **工作原理**: 这是一个加密交换过程，iPhone 使用其硬件中存储的私钥与电脑共同生成证书。如果设备未被信任，iPhone 将只允许通过闪电接口充电，而**不允许任何数据读写**。
    
- **有效期**: 30 天。
    
- **存储位置 (Windows)**: `C:\ProgramData\Apple\Lockdown`
    

##### 2. 锁定与解锁状态 (Locked vs. Unlocked State)

当 iPhone 设置了 FaceID、TouchID 或密码时，其“锁定”状态会启用一系列强大的后台保护措施。

下表总结了 iPhone 在“锁定”状态下提供的保护：

|保护类型|描述|
|---|---|
|**文件加密**|设备上的所有文件在静止时均被加密。需要身份验证才能解密和读取数据。|
|**文件可访问性**|具有 `NSFileProtectionComplete` 或更高级别保护的文件无法访问。只有标记为 `NSFileProtectionNone` 的文件可访问。|
|**硬件访问**|默认拒绝访问麦克风、摄像头等敏感硬件，也无法进行新的蓝牙配对。|
|**应用访问**|仅允许有限的后台应用功能运行，如音乐播放、地图导航等。|
|**钥匙串访问**|iOS 钥匙串中存储的密码等凭证，只有在设备进入“解锁”状态后才能访问。|
|**信任与配对**|将 iPhone 连接到没有现有信任证书的设备时，必须先解锁 iPhone 才能建立信任。|

##### 3. 数据保护类别 (Data Protection Classes)

iOS 通过数据保护类别进一步细化了文件安全性，这些类别决定了文件何时可被读写以及其加密密钥何时可用。

下表总结了四种主要的数据保护类别：

|类别名称|常见用途|访问条件|
|---|---|---|
|`NSFileProtectionNone`|缓存文件|始终可访问，即使设备处于锁定状态。|
|`NSFileProtectionCompleteUnlessOpen`|音频/视频播放应用|文件在设备解锁时被打开，之后即使设备锁定，仍可继续访问。|
|`NSFileProtectionCompleteUntilFirstUserAuthentication`|后台数据读写（如计步、通知）|设备重启后必须至少解锁一次，之后文件在设备锁定时仍可访问。|
|`NSFileProtectionComplete`|凭证、消息、健康数据|**最高安全级别**。文件只有在设备处于解锁状态时才能访问。|

#### 证据保全 (Evidence Preservation)

##### 1. 数据丢失风险

在进行 iPhone 取证时，证据保全至关重要，因为多种安全功能可能导致数据被销毁。

- **远程擦除**: 用户可以通过苹果的 **“查找我的” (Find My)** 应用远程清除丢失或被盗设备上的所有数据。
    
- **本地擦除**: 可以设置 iPhone 在**连续多次输入错误密码**后自动擦除所有数据，以防止暴力破解。
    

##### 2. 备份 (Backups)

在进行任何分析之前，对 iPhone 进行备份是保存和保护证据的**首要步骤**。

- **备份类型**:
    
    - **加密备份**: 备份整个设备，包括账户密码、健康数据、Wi-Fi 密码以及所有常规数据。**这是取证的首选**。
        
    - **未加密备份**: 仅备份照片、应用、音乐等常规数据，不包含敏感信息。
        
- **备份工具**:
    
    - **图形界面**: iTunes, 3uTools, EaseUS 等。
        
    - **命令行**: `libimobiledevice` 框架。
        

##### 3. 物理隔离：法拉第袋 (Physical Isolation: Faraday Bags)

法拉第袋是一种由特殊材料制成的屏蔽袋，可以**阻断所有电磁信号**（如 Wi-Fi、蜂窝网络、蓝牙）。

- **用途**: 将 iPhone 放入法拉第袋中，可以有效防止设备接收到远程擦除命令，确保证据在被分析前不会被篡改或销毁。
    

#### iOS 文件系统 (iOS File System)

##### 1. HFS+ 与 APFS

- **HFS+ (Mac OS Extended)**: 苹果于 1998 年推出的传统文件系统，默认未加密，且缺乏完整性校验。
    
- **APFS (Apple File System)**: 自 2017 年 3 月（iOS 10.3）起，所有 iOS 设备的默认文件系统，具备现代文件系统的诸多特性：
    
    - **全盘加密**: 默认强制加密。
        
    - **完整性检查**: 通过校验和保护元数据和文件。
        
    - **崩溃保护机制**: 提升系统稳定性。
        
    - **智能数据管理**
        

##### 2. 应用程序沙盒 (Application Sandbox)

沙盒是 iOS 安全的核心机制。每个应用程序都在其独立的“容器”中运行，这意味着：

- **数据隔离**: 一个应用无法访问属于另一个应用的数据。
    
- **权限控制**: 应用必须明确请求用户授权才能访问系统资源，如相机、麦克风、照片库等。
    

##### 3. 关键目录结构 (Key Directory Structure)

下表总结了 iOS 中一些重要的目录及其用途：

|目录路径|域|用途|
|---|---|---|
|`/System/Library/`|系统|存放操作系统核心数据，如字体、框架、UI 组件。|
|`/tmp/`|系统|存放临时文件，如日志、崩溃转储、下载缓存等。|
|`/System/Applications/`|系统|存放天气、时钟等预装系统应用的数据。|
|`/Containers/Data/Application/`|用户|存放从 App Store 下载的第三方应用数据，每个应用都在独立的沙盒中。|
|`/Media/`|用户|存放照片、视频、录音、电子书等媒体文件。|
|`/Library/`|用户|存放通讯录、日历、短信、Safari 数据等应用数据。|
|`/Documents/`|用户|存放用户创建或下载的文件，如 PDF、MP3/MP4 等。|

#### 常见文件类型与证据 (Common File Types & Artifacts)

iOS 主要使用 Plists、XML 和 SQLite 数据库来存储数据。

##### 1. 文件类型

- **Plists (属性列表)**: 用于存储结构化数据，有两种格式：
    
    - **XML**: 人类可读。
        
    - **二进制**: 人类不可读，需要专门工具解析。
        
- **SQLite 数据库**: iOS 大量使用 SQLite 数据库来存储各类数据，如照片元数据、短信、联系人等。
    

##### 2. 常见证据位置 (在备份中)

- **联系人**: `/HomeDomain/Library/AddressBook` (SQLite 数据库)
    
- **照片**: `/CameraRollDomain/Media/DCIM`
    
- **日历**: `/HomeDomain/Library/Calendar` (SQLite 数据库)
    
- **Wi-Fi 网络**: `/SystemPreferencesDomain` (Plist 文件，SSID 为明文)
    
- **Safari 浏览器**: `/HomeDomain/Library/Safari` (数据库，包含历史记录和书签)
    

##### 3. 关键目录深度解析 (`/var/` 目录)

- `/var/mobile`: 包含核心用户数据，如文档、库、临时文件。
    
- `/var/keychains`: 存储苹果的“钥匙串”，包含保存的网站凭证、证书和加密密钥。
    
- `/var/logs`: 包含系统日志、应用日志（崩溃报告）、调试信息和更新日志。
    
- `/var/db`: **分析师最感兴趣的目录之一**，存储了大量的 SQLite 数据库文件，包括系统数据库（联系人、消息）和应用数据库。
    

#### 分析工具与方法 (Analysis Tools & Methods)

##### 1. libimobiledevice (命令行工具包)

这是一个跨平台的开源工具包，用于与 iOS 设备进行底层交互。

- **操作流程**:
    
    1. **连接与信任**: 将 iPhone 连接到电脑并完成信任过程。
        
    2. **验证连接**: 使用 `ideviceinfo` 确认设备已连接。
        
    3. **开启加密备份**:
        
        Bash
        
        ```
        idevicebackup2 -i encryption on
        ```
        
    4. **创建完整备份**:
        
        Bash
        
        ```
        idevicebackup2 backup --full ./backup
        ```
        

> **注意**：使用 `libimobiledevice` 创建的备份格式与 iTunes 相同，需要使用 `ideviceunback` 等工具进行解析。

##### 2. 3uTools (图形界面工具)

这是一款功能强大的 Windows 端 iOS 设备管理工具，提供了直观的备份和文件浏览功能。

- **操作流程**:
    
    1. **连接设备**: 将 iPhone 连接到运行 3uTools 的电脑。
        
    2. **创建备份**: 点击 **“备份/恢复” (Backup / Restore)** 图标，配置并开始备份。
        
    3. **查看备份**: 备份完成后，点击 **“查看所有数据备份” (View All-Data Backup)**，选择刚创建的备份进行查看。
        
        - **简单模式 (Simple Mode)**: 提供快速概览。
            
        - **专业模式 (Professional Mode)**: 提供备份中所有文件和数据库的详细视图，是取证分析的核心功能。