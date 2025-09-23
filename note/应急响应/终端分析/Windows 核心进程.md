#### System (PID 4)

##### 正常行为 (Normal Behavior)

`System` 进程是操作系统内核模式线程的宿主。这些特殊的系统线程完全在内核模式下运行，执行加载在系统空间（如 `Ntoskrnl.exe` 或其他设备驱动程序）中的代码。

- **固定 PID**: `System` 进程的进程 ID (PID) **始终为 4**。
    
- **无用户空间**: 它没有用户进程地址空间，所有动态存储都必须从操作系统内存池中分配。
    

##### 异常迹象 (Signs of Abnormality)

- **父进程**: 不应有父进程（除了系统空闲进程 `PID 0`）。
    
- **实例数量**: 系统中只应存在**一个** `System` 进程实例。
    
- **PID**: PID **不为 4**。
    
- **会话**: 不在会话 0 (Session 0) 中运行。
    

#### smss.exe (Windows 会话管理器)

##### 正常行为 (Normal Behavior)

`smss.exe` (Session Manager Subsystem) 是由内核启动的**第一个用户模式进程**，其核心职责是创建新的用户会话。

- 它负责启动 Windows 子系统 (`win32k.sys`, `winsrv.dll`, `csrss.exe`)。
    
- 在会话 0 (系统会话) 中，它启动 `csrss.exe` 和 `wininit.exe`。
    
- 在会话 1 (第一个用户会话) 中，它启动 `csrss.exe` 和 `winlogon.exe`。
    
- 当创建新会话时，`smss.exe` 会复制一个子实例到新会话中，该子实例完成启动任务后会**自行终止**。
    
- 它还负责创建环境变量和虚拟内存分页文件。
    

##### 异常迹象 (Signs of Abnormality)

- **父进程**: 父进程不是 `System` (PID 4)。
    
- **镜像路径**: 路径不是 `C:\Windows\System32`。
    
- **实例数量**: 同时存在多个正在运行的 `smss.exe` 进程（子进程应在会话创建后退出）。
    
- **用户**: 运行用户不是 `SYSTEM`。
    
- **注册表**: `HKLM\System\CurrentControlSet\Control\Session Manager\Subsystems` 键中存在非预期的子系统条目。
    

#### csrss.exe (客户端服务器运行进程)

##### 正常行为 (Normal Behavior)

`csrss.exe` (Client Server Runtime Process) 是 Windows 子系统的用户模式部分，对系统操作至关重要。

- **核心职责**: 负责管理 Win32 控制台窗口、进程和线程的创建与删除、映射驱动器号以及处理 Windows 关机过程。
    
- **父进程**: 由 `smss.exe` 启动，但 `smss.exe` 的子实例在启动它之后会退出，因此 `csrss.exe` 进程通常**没有活动的父进程**。
    
- **系统关键性**: 终止此进程将导致系统蓝屏崩溃。
    

##### 异常迹象 (Signs of Abnormality)

- **父进程**: 存在一个活动的父进程。
    
- **镜像路径**: 路径不是 `C:\Windows\System32`。
    
- **拼写错误**: 出现细微的拼写错误，如 `crss.exe`，这是恶意软件常见的伪装伎俩。
    
- **用户**: 运行用户不是 `SYSTEM`。
    

#### wininit.exe (Windows 初始化进程)

##### 正常行为 (Normal Behavior)

`wininit.exe` 负责在会话 0 中启动三个关键的后台服务：

1. `services.exe` (服务控制管理器)
    
2. `lsass.exe` (本地安全认证)
    
3. `lsaiso.exe` (仅当 Credential Guard 启用时)
    

- **父进程**: 同样由 `smss.exe` 的子实例启动，该子实例随后会退出。
    

##### 异常迹象 (Signs of Abnormality)

- **父进程**: 存在一个活动的父进程。
    
- **镜像路径**: 路径不是 `C:\Windows\System32`。
    
- **拼写错误**: 存在伪装的拼写错误。
    
- **用户**: 运行用户不是 `SYSTEM`。
    
- **实例数量**: 存在多个正在运行的实例。
    

#### services.exe (服务控制管理器)

##### 正常行为 (Normal Behavior)

`services.exe` (Service Control Manager, SCM) 的主要职责是管理系统服务（加载、启动、停止、交互）。

- **父进程**: `wininit.exe`。
    
- **注册表**: 服务的详细信息存储在 `HKLM\System\CurrentControlSet\Services`。
    
- **子进程**: 它是许多关键系统进程的父进程，最典型的就是 `svchost.exe`，此外还有 `spoolsv.exe` (打印服务), `msmpeng.exe` (Windows Defender) 等。
    

##### 异常迹象 (Signs of Abnormality)

- **父进程**: 父进程不是 `wininit.exe`。
    
- **镜像路径**: 路径不是 `C:\Windows\System32`。
    
- **拼写错误**: 存在伪装的拼写错误。
    
- **用户**: 运行用户不是 `SYSTEM`。
    
- **实例数量**: 存在多个正在运行的实例。
    

#### svchost.exe (服务主机进程)

##### 正常行为 (Normal Behavior)

`svchost.exe` (Service Host) 本身不执行任何功能，它的作用是作为**宿主进程**来运行那些以动态链接库 (DLL) 形式实现的服务。

- **父进程**: `services.exe`。
    
- **服务分组**: 为了节约资源，多个服务可以通过 `-k <GroupName>` 参数共享同一个 `svchost.exe` 进程。`GroupName` 定义在服务的注册表项中。
    
    > **注意**: 在内存大于 3.5 GB 的现代 Windows 系统上，许多服务会各自运行在独立的 `svchost.exe` 进程中。
    
- **DLL 路径**: 服务的具体 DLL 路径存储在 `HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE NAME>\Parameters` 下的 `ServiceDLL` 值中。
    

##### 异常迹象 (Signs of Abnormality)

- **父进程**: 父进程不是 `services.exe`。
    
- **镜像路径**: 路径不是 `C:\Windows\System32`。
    
- **拼写错误**: 出现如 `scvhost.exe` 等伪装名称。
    
- **命令行**: **缺少 `-k` 参数**。
    
- **服务**: 其托管的服务（DLL）指向一个可疑或未知的文件路径。
    

#### lsass.exe (本地安全认证子系统服务)

##### 正常行为 (Normal Behavior)

`lsass.exe` (Local Security Authority Subsystem Service) 是负责执行系统安全策略的核心进程。

- **核心职责**: 验证用户登录、处理密码更改、创建访问令牌，并将安全事件写入 Windows 安全日志。
    
- **父进程**: `wininit.exe`。
    
- **攻击目标**: 它是 `mimikatz` 等凭证窃取工具的主要攻击目标。
    

##### 异常迹象 (Signs of Abnormality)

- **父进程**: 父进程不是 `wininit.exe`。
    
- **镜像路径**: 路径不是 `C:\Windows\System32`。
    
- **拼写错误**: 存在伪装的拼写错误。
    
- **实例数量**: 存在多个正在运行的实例。
    
- **用户**: 运行用户不是 `SYSTEM`。
    

#### winlogon.exe (Windows 登录进程)

##### 正常行为 (Normal Behavior)

`winlogon.exe` 负责处理**安全注意序列 (SAS)**，即用户按下 `CTRL+ALT+DELETE` 的操作。

- **核心职责**: 管理用户登录和注销，加载用户配置文件（将 `NTUSER.DAT` 加载到 `HKCU`），以及负责锁定屏幕和运行屏保。
    
- **父进程**: 由 `smss.exe` 的子实例启动，该子实例随后会退出。
    

##### 异常迹象 (Signs of Abnormality)

- **父进程**: 存在一个活动的父进程。
    
- **镜像路径**: 路径不是 `C:\Windows\System32`。
    
- **拼写错误**: 存在伪装的拼写错误。
    
- **用户**: 运行用户不是 `SYSTEM`。
    
- **注册表**: `Winlogon\Shell` 注册表项的值被修改为除 `explorer.exe` 之外的其他程序。
    

#### explorer.exe (Windows 资源管理器)

##### 正常行为 (Normal Behavior)

`explorer.exe` 是用户的默认 Shell，提供了图形用户界面，如桌面、任务栏、开始菜单以及文件浏览器。

- **父进程**: `explorer.exe` 由 `userinit.exe` 启动，而 `userinit.exe` 在成功启动 `explorer.exe` 后会**立即退出**。因此，正常的 `explorer.exe` 进程**没有父进程**。
    
- **用户**: 以当前登录用户的身份运行。
    

##### 异常迹象 (Signs of Abnormality)

- **父进程**: **存在一个活动的父进程**。
    
- **镜像路径**: 路径不是 `C:\Windows`。
    
- **用户**: 以非当前登录用户的身份运行。
    
- **拼写错误**: 存在伪装的拼写错误。
    
- **网络连接**: **存在出站 TCP/IP 连接**。`explorer.exe` 通常不应直接发起网络连接。