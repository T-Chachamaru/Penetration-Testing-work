#### 概述 (Overview)

一旦通过初始访问获得了一组有效的活动目录 (Active Directory, AD) 凭证，攻击的下一阶段便是**已认证枚举 (Authenticated Enumeration)**。即便使用非常低权限的账户，攻击者也能查询 AD 的结构、配置和对象，从而打开一个充满可能性的新世界。

在红队演练中，枚举的目标是发现配置错误、识别高权限目标，并最终绘制出可行的攻击路径。这些路径可能用于**权限提升 (Privilege Escalation)** 或**横向移动 (Lateral Movement)**，以获取更多访问权限，直至达成最终目标。枚举与利用通常是紧密交织、循环往复的过程：每次成功的利用都会提供一个新的、权限更高的立足点，攻击者会从该位置再次开始新一轮的枚举。

#### 准备工作：凭证注入 (Preparation: Credential Injection)

在安全评估中，攻击者控制的机器通常未加入目标域。为了使用已获取的 AD 凭证进行网络认证，需要先将其注入到当前会话的内存中。

- **使用 `runas` 命令 (Using the `runas` Command)**：
    
    - `runas.exe` 是一个合法的 Windows 内置程序，可用于此目的。它允许以另一个用户的身份运行程序。
    - **命令结构**：
        
        Bash
        
        ```
        runas.exe /netonly /user:<domain_fqdn>\<username> cmd.exe
        ```
        
    - **关键参数**：
        - `/netonly`：此参数至关重要。它指示 `runas` 仅将凭证用于**网络认证**。本地执行的命令仍在当前用户上下文中运行，但任何出站网络连接都将使用注入的凭证。由于凭证不会立即被验证，系统会接受任何输入的密码。
        - `/user`：指定目标域的完全限定域名 (FQDN) 和用户名。使用 FQDN（如 `za.tryhackme.com`）而非 NetBIOS 名称（如 `ZA`）是最佳实践。
        - `cmd.exe`：在凭证注入后启动的程序。启动一个新的命令提示符 (`cmd.exe`) 是最灵活的选择。
- **DNS 配置与凭证验证 (DNS Configuration and Credential Validation)**：
    
    - **DNS 配置**：为了能通过域名访问域资源（如域控制器），必须将攻击机的 DNS 服务器指向目标域的域控制器 (DC)。
        
        PowerShell
        
        ```
        # 假设 $dc_ip 是域控制器的 IP 地址
        $dnsip = "<DC_IP>"
        $index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
        Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
        ```
        
    - **凭证验证**：验证凭证是否有效且已成功注入的最佳方法是尝试访问 `SYSVOL` 共享目录。`SYSVOL` 是存在于所有 DC 上的共享文件夹，存储组策略对象 (GPO) 和域脚本，任何经过身份验证的域用户（无论权限多低）都具有读取权限。
        
        Bash
        
        ```
        # 如果此命令成功列出目录内容，则证明凭证有效且网络连接正常
        dir \\za.tryhackme.com\SYSVOL\
        ```
        
- **主机名 vs. IP 地址：认证协议的选择 (Hostname vs. IP Address: Choosing Authentication Protocol)**：
    
    - **Kerberos (使用主机名)**：当使用 FQDN 访问资源时（`\\za.tryhackme.com\SYSVOL`），Windows 会优先尝试使用 **Kerberos** 协议进行认证。
    - **NTLM (使用 IP 地址)**：当使用 IP 地址访问资源时（`\\<DC_IP>\SYSVOL`），Windows 会回退到使用 **NTLM** 协议进行认证。
    - **操作安全 (OPSEC) 意义**：了解并控制所使用的认证协议对于高级攻击者至关重要。在某些情况下，强制使用 NTLM 可以绕过针对 Kerberos 特定攻击（如 Pass-The-Ticket）的监控，从而提高隐蔽性。

#### 枚举方法 (Enumeration Methods)

##### 通过微软管理控制台 (Enumeration via Microsoft Management Console, MMC)

- **概述 (Overview)**：MMC 提供了一个图形化界面来浏览和管理 AD 对象。必须从已注入凭证的 `runas` 命令提示符窗口中启动 (`mmc.exe`)，以确保其网络连接使用正确的凭证。
- **配置流程 (Configuration Steps)**：
    1. 在 MMC 中，点击 `文件` -> `添加/删除管理单元`。
    2. 选择并添加 `Active Directory 域和信任`、`Active Directory 站点和服务`、`Active Directory 用户和计算机` 三个管理单元。
    3. 右键单击 `Active Directory 域和信任`，选择 `更改林`，输入目标 FQDN。
    4. 右键单击 `Active Directory 站点和服务`，选择 `更改林`，输入目标 FQDN。
    5. 右键单击 `Active Directory 用户和计算机`，选择 `更改域`，输入目标 FQDN。
    6. 右键单击 `Active Directory 用户和计算机`，选择 `查看` -> `高级功能` 以显示所有属性和对象。
- **优点与缺点 (Pros and Cons)**：
    - **优点**：提供直观的 GUI 视图；可快速搜索对象；若权限足够，可直接修改对象。
    - **缺点**：通常需要 RDP 访问；难以进行大规模、跨对象的属性收集和分析。

##### 通过命令提示符 (Enumeration via Command Prompt, CMD)

- **概述 (Overview)**：使用内置的 `net.exe` 命令是在受限环境（如 RAT 会话或 PowerShell 被严密监控的场景）下进行快速查询的有效手段。
- **用户枚举 (User Enumeration)**：
    - `net user /domain`：列出域中的所有用户。
    - `net user <username> /domain`：显示特定用户的详细信息，包括组成员身份（有限）、密码策略等。
- **组枚举 (Group Enumeration)**：
    - `net group /domain`：列出域中的所有组。
    - `net group "<groupname>" /domain`：显示特定组的成员。
- **密码策略枚举 (Password Policy Enumeration)**：
    - `net accounts /domain`：显示域的默认密码策略，如最小密码长度、密码历史、锁定阈值等。这些信息对于规划后续的密码喷洒攻击至关重要。
- **优点与缺点 (Pros and Cons)**：
    - **优点**：无需额外工具，通常不被严密监控，易于在宏或钓鱼载荷中脚本化。
    - **缺点**：功能相对有限，例如当用户属于大量组时，可能无法显示所有组成员身份。

##### 通过 PowerShell (Enumeration via PowerShell)

- **概述 (Overview)**：PowerShell 及其 AD 模块（需要安装 RSAT 工具）提供了比 CMD 强大得多的枚举能力，支持复杂的过滤和对象操作。
- **核心 Cmdlets**：
    - `Get-ADUser`：枚举用户。`-Properties *` 可显示所有属性，`-Filter` 支持复杂的查询。
        
        PowerShell
        
        ```
        # 查找所有姓氏为 "stevens" 的用户
        Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A
        ```
        
    - `Get-ADGroup` / `Get-ADGroupMember`：枚举组及其成员。
    - `Get-ADObject`：通用的对象查询工具，可用于查找满足特定条件的任何对象。
        
        PowerShell
        
        ```
        # 查找所有密码错误次数大于 0 的账户，以在密码喷洒中避开它们
        Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com
        ```
        
    - `Get-ADDomain`：获取有关域本身的信息。
    - `Set-ADAccountPassword`：修改 AD 对象的示例，可用于重置密码（若有权限）。
- **优点与缺点 (Pros and Cons)**：
    - **优点**：信息量远超 CMD；支持复杂查询；可远程执行（使用 `-Server` 参数）；功能可扩展；可直接修改对象。
    - **缺点**：PowerShell 活动受到蓝队更严密的监控；需要安装 AD-RSAT 工具或加载外部脚本（如 PowerView），可能被检测。

##### 通过 BloodHound (Enumeration via BloodHound)

- **概述 (Overview)**：BloodHound 是一种革命性的工具，它将 AD 环境可视化为攻击图谱，使攻击者能够以“图思维”方式发现复杂的攻击路径，而不是依赖传统的列表。这使得高度精确、快速的攻击成为可能。
- **SharpHound：数据收集器 (SharpHound: The Data Collector)**：
    - **定义**：SharpHound 是 BloodHound 的数据收集组件，负责查询 AD 并生成可供 BloodHound 使用的 JSON 文件。
    - **执行**：由于 SharpHound 本身是敏感工具，容易被 AV/EDR 检测，最佳实践是在受控的、已注入凭证的非域成员主机上运行它。
        
        Bash
        
        ```
        # --CollectionMethods All 会执行所有收集模块
        # --ExcludeDCs 避免直接与域控制器交互，降低被检测风险
        SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs
        ```
        
    - **数据更新**：AD 结构不常变，但用户会话（Session）是动态的。建议在评估开始时运行一次 `All` 收集，之后每天定期运行 `Session` 收集，以获取最新的会话数据。
- **BloodHound：数据可视化与分析 (BloodHound: Data Visualization and Analysis)**：
    - **定义**：BloodHound 是一个 GUI 工具，它使用 Neo4j 图数据库作为后端，将 SharpHound 收集的数据导入并可视化。
    - **启动与导入**：先启动 `neo4j` 服务，然后运行 `bloodhound` 客户端。将 SharpHound 生成的 ZIP 文件拖放到 GUI 中即可导入数据。
    - **核心概念**：
        - **节点 (Nodes)**：代表 AD 对象（用户、组、计算机等）。
        - **边 (Edges)**：代表对象之间的关系或权限（如 `MemberOf`, `HasSession`, `GenericAll`）。
    - **攻击路径分析**：BloodHound 最强大的功能是其内置的路径查找能力。通过指定起始节点（如攻击者已控制的账户）和目标节点（如 `Domain Admins` 组），它可以自动计算出最短的攻击路径。
        - **示例**：发现路径 `gordon.stevens` -> (`MemberOf`) -> `DOMAIN USERS` -> (`GenericRDP`) -> `THMJMP1` <- (`HasSession`) <- `t1_arthur.tyler`。
        - **解读**：这表示 `gordon.stevens` 用户可以通过 RDP 连接到 `THMJMP1` 主机，而 `THMJMP1` 上有一个 Tier 1 管理员的活动会话。
        - **利用**：据此可制定攻击计划：1. RDP 登录 `THMJMP1`。2. 在主机上提权至本地管理员。3. 使用 Mimikatz 等工具从内存中抓取 Tier 1 管理员的凭证。
- **优点与缺点 (Pros and Cons)**：
    - **优点**：提供无与伦比的攻击路径可视化能力；能揭示手动查询难以发现的复杂权限关系；极大提升了攻击规划的效率和精确度。
    - **缺点**：其数据收集器 SharpHound 活动**非常嘈杂**，极易被现代 EDR 和安全监控解决方案检测和阻止。