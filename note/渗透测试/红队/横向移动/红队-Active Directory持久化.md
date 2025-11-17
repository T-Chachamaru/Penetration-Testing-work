
#### 目录
- [通过凭证复制实现持久化](#通过凭证复制实现持久化-persistence-via-credential-replication)
- [通过 Kerberos 票据实现持久化](#通过-kerberos-票据实现持久化-persistence-via-kerberos-tickets)
- [通过 AD 证书服务实现持久化](#通过-ad-证书服务实现持久化-persistence-via-ad-certificate-services)
- [通过 SID 历史实现持久化](#通过-sid-历史实现持久化-persistence-via-sid-history)
- [通过隐蔽的组成员资格实现持久化](#通过隐蔽的组成员资格实现持久化-persistence-via-covert-group-membership)
- [通过 ACL 和 GPO 实现持久化](#通过-acl-和-gpo-实现持久化-persistence-via-acls-and-gpos)

#### 概述 (Overview)

**持久化 (Persistence)** 是指攻击者在获得初始访问权限后，为确保能够长期、稳定地返回目标网络而采取的一系列技术。其核心目标是，即使最初的入口点被发现并封堵，或被盗用的凭证被重置，攻击者仍能维持其访问权限。

在 AD 环境中，高明的持久化策略并不仅仅是守住一个域管理员 (DA) 账户。高权限账户往往受到最严密的监控，其凭证也最先被轮换。因此，更隐蔽、更具韧性的持久化目标包括：

- **拥有广泛本地管理员权限的账户**：控制了能够管理大量工作站或服务器的账户，等于保留了在网络中横向移动的能力。
- **拥有委派权限的服务账户**：这些账户可被用于执行 Kerberos 委派攻击，再次获取高权限访问。
- **控制关键基础设施服务的账户**：如 Exchange、SCCM 或 AD CS 服务的账户，这些服务本身就可以作为再次入侵域的强大跳板。

---

#### 通过凭证复制实现持久化 (Persistence via Credential Replication)

- **DCSync 攻击 (The DCSync Attack)**：
    - **基本原理 (Fundamentals)**: 在一个多域控制器 (DC) 的环境中，DC 之间会通过一个名为**域复制 (Domain Replication)** 的过程来同步 AD 数据库（包括所有用户的密码哈希）。拥有“复制目录更改”权限的账户（默认包括域管理员、域控等）可以模拟一个 DC，向另一个 DC 请求用户凭证数据。这个过程被称为 `DCSync`。
    - **执行攻击 (Execution)**: 攻击者一旦获得具备该权限的账户，就可以使用 Mimikatz 等工具，从网络的任何位置发起 DCSync 攻击，从而转储域中所有账户的密码哈希，而无需登录到 DC 本身。
        
        PowerShell
        
        ```
        # 在 Mimikatz 中
        # 启用日志记录
        log dcsync_dump.txt
        
        # 使用 /all 参数转储域中所有账户的凭证数据
        lsadump::dcsync /domain:za.tryhackme.loc /all
        
        # 退出以保存日志
        exit
        ```
        
    - **持久化价值 (Persistence Value)**: 通过定期执行 DCSync，攻击者可以持续获取域中所有账户的最新密码哈希，使其对凭证轮换免疫。

---

#### 通过 Kerberos 票据实现持久化 (Persistence via Kerberos Tickets)

- **黄金票据 (Golden Tickets)**：
    
    - **基本原理 (Fundamentals)**: 黄金票据是一种**伪造的票据授予票据 (Forged TGT)**。它使用从 DC 窃取的 `krbtgt` 账户的 NTLM 哈希进行签名。由于域中所有 TGT 都由 `krbtgt` 账户签名，因此任何拥有此哈希的攻击者都可以为域内**任意用户**（甚至是不存在的用户）签发有效的 TGT，从而完全绕过正常的身份验证流程。
    - **攻击优势 (Attack Advantages)**:
        - **长期有效**：可以设置长达数年的有效期。
        - **权限伪造**：可以任意指定用户身份和所属用户组。
        - **高度隐蔽**：生成过程完全离线，不与 DC 交互。
        - **绕过防御**：可以绕过智能卡等多因素认证。
    - **防御与修复 (Defense and Remediation)**: 唯一有效的修复方法是**重置 `krbtgt` 账户的密码两次**。这是一个对生产环境影响极大的操作，因为它会立即使域中所有现存的 Kerberos 票据失效。
- **白银票据 (Silver Tickets)**：
    
    - **基本原理 (Fundamentals)**: 白银票据是一种**伪造的服务票据 (Forged TGS)**。它使用目标**服务**自身的密码哈希（例如，文件服务器的计算机账户哈希）进行签名。
    - **攻击优势与限制 (Attack Advantages and Limitations)**:
        - **范围有限**：一张白银票据只能用于访问签发它的特定服务（如 `CIFS/server.domain.com`）。
        - **极其隐蔽**：由于验证过程仅在客户端和目标服务之间进行，完全**不涉及与 DC 的通信**，因此在网络层面几乎无法被检测到。
    - **持久化策略 (Persistence Strategy)**: 虽然计算机账户密码默认每 30 天轮换一次，但拥有目标主机管理员权限的攻击者可以修改注册表来禁用密码轮换，从而使白银票据能够长期有效。
- **示例：伪造黄金与白银票据 (Example: Forging Golden and Silver Tickets)**：
    
    - **伪造黄金票据 (Forging a Golden Ticket)**:
        
        PowerShell
        
        ```
        # 在 Mimikatz 中，使用获取到的 krbtgt 哈希和域 SID
        kerberos::golden /admin:FakeAdmin /domain:za.tryhackme.loc /sid:<Domain_SID> /krbtgt:<KRBTGT_NTLM_Hash> /id:500 /ptt
        ```
        
    - **伪造白银票据 (Forging a Silver Ticket)**:
        
        PowerShell
        
        ```
        # 在 Mimikatz 中，使用目标主机的计算机账户哈希
        kerberos::golden /admin:FakeAdmin /domain:za.tryhackme.loc /sid:<Domain_SID> /target:THMSERVER1.za.tryhackme.loc /service:cifs /rc4:<THMSERVER1$_NTLM_Hash> /id:500 /ptt
        ```
        

---

#### 通过 AD 证书服务实现持久化 (Persistence via AD Certificate Services)

- 基本原理 (Fundamentals)：
    
    这是最高级别、最具破坏性的持久化技术之一。攻击者如果能够窃取证书颁发机构 (CA) 的根证书及其私钥，就相当于成为了域中信任的根源。他们可以为任意用户签发有效的证书，用于身份验证，从而获得持久的、几乎无法被吊销的访问权限。
    
- **示例：窃取 CA 私钥并伪造证书 (Example: Stealing the CA Private Key and Forging Certificates)**：
    
    - **私钥提取 (Private Key Extraction)**:
        1. 在被攻陷的 CA 服务器上，运行 Mimikatz。
        2. 使用 `crypto::capi` 和 `crypto::cng` 对内存进行修补，以允许导出被标记为不可导出的私钥。
        3. 使用 `crypto::certificates /systemstore:local_machine /export` 命令，将 CA 证书及其私钥导出为 `.pfx` 文件。Mimikatz 导出的默认密码是 `mimikatz`。
    - **伪造证书 (Forging a Certificate)**: 使用 `ForgeCert.exe` 等工具和窃取的 CA 证书 (`.pfx` 文件)，为目标高权限用户（如 `Administrator`）签发一个新的客户端认证证书。
        
        Bash
        
        ```
        ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword mimikatz --Subject CN=FakeUser --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath admin_cert.pfx --NewCertPassword NewPassword123
        ```
        
    - **利用伪造证书 (Using the Forged Certificate)**: 使用 `Rubeus` 等工具，凭此伪造的证书请求一个 Kerberos TGT，然后通过 `Pass-the-Ticket` 使用该 TGT。
    - **防御与修复 (Defense and Remediation)**: 由于该证书是攻击者私下签发的，并未记录在 CA 的已颁发证书数据库中，因此**无法被吊销**。唯一的根除方法是废除整个 CA，重新建立 PKI 体系，并重新颁发所有证书，这对任何组织来说都是一场灾难。

---

#### 通过 SID 历史实现持久化 (Persistence via SID History)

- 基本原理 (Fundamentals)：
    
    sIDHistory 是一个用于 AD 迁移的账户属性，它允许一个新账户保留其旧账户的 SID，从而维持对旧资源的访问权限。攻击者可以滥用此功能，将一个高权限组（如 Domain Admins）的 SID 注入到一个低权限账户的 sIDHistory 属性中。当该低权限账户登录时，其访问令牌会包含这个高权限组的 SID，从而获得该组的所有权限，但账户本身并不显示为该组的成员，这使其极为隐蔽。
    
- **示例：注入 SID 历史 (Example: Injecting SID History)**：
    
    - **执行 (Execution)**: 此操作需要域管理员权限。可以使用 `DSInternals` 等工具集，在 DC 上直接修改 `ntds.dit` 数据库。
        
        PowerShell
        
        ```
        # 1. 停止 NTDS 服务以解锁数据库文件
        Stop-Service -Name ntds -Force
        
        # 2. 使用 DSInternals 向目标账户添加 SID 历史
        Add-ADDBSidHistory -SamAccountName 'low_priv_user' -SidHistory 'S-1-5-21-...-512' -DatabasePath 'C:\Windows\NTDS\ntds.dit'
        
        # 3. 重新启动 NTDS 服务
        Start-Service -Name ntds
        ```
        
    - **防御与检测 (Defense and Detection)**: 检测此技术需要主动扫描用户对象的 `sIDHistory` 属性，寻找不应存在的条目。常规的组成员检查无法发现此异常。

---

#### 通过隐蔽的组成员资格实现持久化 (Persistence via Covert Group Membership)

- 基本原理 (Fundamentals)：
    
    直接将会员添加到 Domain Admins 等顶级权限组容易触发警报。一种更隐蔽的方法是利用嵌套组 (Nested Groups)。攻击者可以将一个受控账户添加到一个层级很深、不引人注意的普通用户组中，而这个普通用户组又被嵌套在另一个组中，经过多层嵌套后，最终成为顶级权限组的成员。
    
- 示例：创建嵌套组 (Example: Creating Nested Groups)：
    
    攻击者可以创建一个新的组链 GroupA -> GroupB -> GroupC -> GroupD，其中 GroupA 是 GroupB 的成员，以此类推。然后将 GroupD 添加到 Domain Admins，最后将受控账户添加到最初的 GroupA 中。这使得追踪有效权限变得非常困难，容易绕过简单的成员资格监控。
    

---

#### 通过 ACL 和 GPO 实现持久化 (Persistence via ACLs and GPOs)

- **AdminSDHolder 攻击 (The AdminSDHolder Attack)**：
    
    - **基本原理 (Fundamentals)**: `AdminSDHolder` 是一个特殊的容器对象，其访问控制列表 (ACL) 是一个安全模板。一个名为 `SDProp` 的后台进程会每隔 60 分钟（默认）运行一次，将 `AdminSDHolder` 的 ACL 强制复制到所有“受保护组”（如 Domain Admins, Enterprise Admins 等）上，覆盖这些组现有的任何权限设置。
    - **执行攻击 (Execution)**: 攻击者可以在 `AdminSDHolder` 对象的 ACL 上为自己控制的低权限账户添加 `FullControl` 权限。这样，即使防御者发现了并清除了攻击者在 `Domain Admins` 组上的权限，一小时内 `SDProp` 进程会自动将其恢复，形成一种顽固的持久化。
- **GPO 攻击 (The GPO Attack)**：
    
    - **基本原理 (Fundamentals)**: 组策略对象 (GPO) 可用于向大量计算机统一部署配置，包括执行登录脚本。攻击者可以创建一个恶意 GPO，例如，配置一个登录脚本来执行后门程序。
    - **加固与隐藏 (Hardening and Hiding)**: 更进一步，攻击者可以修改该恶意 GPO 本身的**委派权限**，移除所有管理员组的编辑权限，仅保留 `Authenticated Users` 或更隐蔽的 `Domain Computers` 的读取权限。这使得 GPO 对其他管理员变得“不可见”且难以修改或删除，即使被发现，清理工作也变得极其困难。