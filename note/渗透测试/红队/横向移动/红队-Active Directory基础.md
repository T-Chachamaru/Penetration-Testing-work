
#### 目录
- [活动目录](#活动目录-active-directory)
- [活动目录管理](#活动目录管理-managing-active-directory)
- [组策略](#组策略-group-policy)
- [认证协议](#认证协议-authentication-protocols)
- [域的高级结构](#域的高级结构-advanced-domain-structures)

#### 概述 (Overview)

在大型企业网络环境中，独立管理每台计算机和用户账户是不现实的。随着设备和用户数量的增长，手动配置、策略更新和现场支持变得极其低效且容易出错。为了解决这一挑战，引入了 Windows 域（Windows Domain）的概念。

简单来说，Windows 域是在单一企业管理下的一组用户和计算机的集合。其核心思想是通过一个名为**活动目录 (Active Directory, AD)** 的中央存储库，来集中管理 Windows 网络中的所有常见组件。运行活动目录服务的服务器被称为**域控制器 (Domain Controller, DC)**。

配置 Windows 域的主要优势包括：

- **集中身份管理 (Centralized Identity Management)**：网络中的所有用户账户都可以在活动目录中进行统一创建、配置和管理。
- **统一策略部署 (Unified Policy Deployment)**：安全策略和配置基线可以通过活动目录直接定义，并强制应用于网络中的指定用户和计算机。

#### 活动目录 (Active Directory)

任何 Windows 域的核心都是**活动目录域服务 (Active Directory Domain Services, AD DS)**。该服务充当一个目录，存储了网络中所有“对象”的信息。在 AD 支持的众多对象中，关键的包括用户、组和计算机。

- **用户 (Users)**：
    
    - 用户是活动目录中最常见的对象类型之一，属于**安全主体 (Security Principal)**，意味着它们可以被域认证，并被授予对文件、打印机等资源的访问权限。
    - 用户对象可以代表两种实体：
        - **人员 (People)**：代表需要访问网络资源的组织成员，如员工。
        - **服务 (Services)**：为特定服务（如 IIS 网站或 MSSQL 数据库）运行而定义的服务账户，通常拥有最小化的必要权限。
- **计算机 (Machines)**：
    
    - 当一台计算机加入域时，系统会为其创建一个计算机对象。计算机同样被视为**安全主体**，拥有一个在域内权限受限的账户。
    - 计算机账户名遵循特定格式：计算机名后跟一个美元符号（`$`）。例如，名为 `DC01` 的计算机，其账户名为 `DC01$`。其密码通常是120位的随机字符，并由系统自动轮换。
- **安全组 (Security Groups)**：
    
    - 安全组是用于权限管理的对象，允许将访问权限分配给一组用户或计算机，而非单个对象，从而简化了权限管理。当用户被添加到一个组时，他们会自动继承该组的所有权限。
    - 组可以包含用户、计算机，甚至其他组。域中存在一些默认的关键组：
        - **Domain Admins**：对整个域拥有完全的管理权限，默认可以管理域内任何计算机，包括域控制器。
        - **Server Operators**：可以管理域控制器，但不能修改管理员组的成员资格。
        - **Backup Operators**：可以访问任何文件（忽略其权限），用于执行数据备份。
        - **Account Operators**：可以创建或修改域中的用户和组账户。
        - **Domain Users**：默认包含域中所有用户账户。
        - **Domain Computers**：默认包含域中所有计算机账户。
        - **Domain Controllers**：包含域上所有的域控制器。

#### 活动目录管理 (Managing Active Directory)

要配置 AD 中的对象，管理员通常登录到域控制器并使用“Active Directory Users and Computers”管理单元。

- **组织单元 (Organizational Units, OUs)**：
    
    - **是什么**：OU 是 AD 中的容器对象，用于组织和归类用户、计算机和其他对象。OUs 的主要目的是将具有相似管理需求的对象（如同一部门的用户）分组，以便于应用特定的策略。
    - **结构**：OU 的结构通常模仿企业的组织架构（如 IT、销售、市场部门），因为这样可以高效地为整个部门部署基线策略。一个对象一次只能属于一个 OU。
    - **默认容器**：除了自定义的 OU，AD 还包含一些默认容器，如 `Builtin`（默认组）、`Computers`（新加入域的计算机的默认位置）、`Domain Controllers`（域控制器的默认 OU）和 `Users`（默认用户和组）。
- **安全组与组织单元的区别 (Security Groups vs. Organizational Units)**：
    
    - **OUs**：主要用于**应用策略**。将一组用户或计算机放入同一个 OU，是为了对它们应用统一的组策略（GPO）。一个对象一次只能属于一个 OU。
    - **安全组**：主要用于**授予权限**。将用户放入一个安全组，是为了授予他们对特定资源（如共享文件夹、打印机）的访问权限。一个用户可以是多个组的成员。
- **管理 AD 中的用户 (Managing Users in AD)**：
    
    - **删除 (Deletion)**：默认情况下，OU 受到“防止意外删除”的保护。要删除一个 OU，必须先在“Active Directory Users and Computers”的“查看”菜单中启用“高级功能”，然后在该 OU 的“属性” -> “对象”选项卡中取消勾选保护复选框。
    - **委派 (Delegation)**：委派是授予特定用户对某个 OU 的有限管理权限的过程，而无需赋予其完全的域管理员权限。一个常见的场景是授权 IT 支持人员重置特定部门用户的密码。这可以通过右键单击 OU 并选择“委派控制”来实现。委派后，被授权的用户（如 `phillip`）可以使用 PowerShell 等工具执行其被授予的任务，即使他们没有权限直接打开“Active Directory Users and Computers”工具。
        
        PowerShell
        
        ```
        # 使用 phillip 的账户为 sophie 重置密码
        PS C:\Users\phillip> Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose
        
        # 强制 sophie 在下次登录时更改密码
        PS C:\Users\phillip> Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose
        ```
        
- **管理 AD 中的计算机 (Managing Computers in AD)**：
    
    - 默认情况下，所有加入域的计算机（域控制器除外）都位于 `Computers` 容器中。最佳实践是根据其用途将它们移动到不同的 OU 中，以便应用不同的策略。
    - 常见的分类包括：
        1. **工作站 (Workstations)**：普通用户用于完成日常工作的设备。
        2. **服务器 (Servers)**：向用户或其他服务器提供服务的设备。
        3. **域控制器 (Domain Controllers)**：管理活动目录的核心设备，存储所有账户的密码哈希，是网络中最敏感的资产。

#### 组策略 (Group Policy)

组策略是 Windows 中用于定义和控制用户和计算机工作环境的机制。

- **组策略对象 (Group Policy Objects, GPOs)**：
    
    - **是什么**：GPO 是一组可以链接到一个或多个 OU 的配置设置集合。GPO 可以包含针对计算机的策略（在计算机启动时应用）和针对用户的策略（在用户登录时应用）。
    - **管理**：使用“组策略管理”工具，可以创建 GPO，然后将其链接到目标 OU。还可以通过**安全筛选 (Security Filtering)**，使 GPO 仅应用于 OU 内的特定用户或计算机组。
- **GPO 分发 (GPO Distribution)**：
    
    - GPO 通过一个名为 `SYSVOL` 的特殊网络共享进行分发，该共享存在于每个域控制器上（通常路径为 `C:\Windows\SYSVOL\sysvol\`）。
    - 客户端计算机会定期（默认 90-120 分钟）从 DC 同步 GPO。要强制立即更新，可以在客户端上运行以下命令：
        
        PowerShell
        
        ```
        PS C:\> gpupdate /force
        ```
        

#### 认证协议 (Authentication Protocols)

当用户使用域凭据访问网络服务时，服务需要与 DC 通信以验证凭据。Windows 域主要使用两种网络认证协议。

- **Kerberos 认证 (Kerberos Authentication)**：
    
    - **概述**：当前 Windows 版本的默认认证协议，基于“票据”机制工作。
    - **流程**：
        1. 用户向密钥分发中心（KDC，通常在 DC 上）请求一个**票据授予票据 (Ticket-Granting Ticket, TGT)**。此请求使用用户密码的哈希进行加密。
        2. KDC 返回一个 TGT（使用 `krbtgt` 账户的密码哈希加密）和一个**会话密钥**。TGT 允许用户在不重新输入密码的情况下请求其他票据。
        3. 当用户需要访问特定服务（如文件共享）时，它会向 KDC 出示 TGT，并请求一个**服务票据 (Ticket-Granting Service, TGS)**。
        4. KDC 验证 TGT 后，返回一个 TGS（使用服务所有者账户的密码哈希加密）和一个**服务会话密钥**。
        5. 用户将 TGS 呈现给目标服务。服务使用自己的账户密码哈希解密 TGS，验证票据并授权访问。
- **NetNTLM 认证 (NetNTLM Authentication)**：
    
    - **概述**：一个较旧的、为兼容性而保留的认证协议，基于“挑战-响应”机制。
    - **流程**：
        1. 客户端向服务器发送认证请求。
        2. 服务器生成一个随机数（**挑战**）并发送给客户端。
        3. 客户端使用其 NTLM 密码哈希加密该挑战，生成一个**响应**，并将其发回服务器。
        4. 服务器将客户端的响应和原始挑战转发给 DC。
        5. DC 使用其存储的用户密码哈希重新计算响应，并与客户端发来的响应进行比较。如果匹配，则认证成功。
        6. DC 将认证结果返回给服务器，服务器再通知客户端。

#### 域的高级结构 (Advanced Domain Structures)

随着组织规模的扩大，单一域可能无法满足管理需求，此时需要更复杂的 AD 结构。

- **树 (Trees)**：
    
    - **是什么**：当多个域共享同一个连续的 DNS 命名空间时，它们组成一个**树**。例如，`thm.local` 是根域，而 `uk.thm.local` 和 `us.thm.local` 是其子域，共同构成一棵树。
    - **优势**：允许对不同地理位置或业务单元进行分区管理。英国的域管理员可以管理 `uk.thm.local`，但不能管理 `us.thm.local`。
    - **企业管理员 (Enterprise Admins)**：这是一个存在于林根域中的特殊组，其成员对森林中所有域都拥有管理权限。
- **森林 (Forests)**：
    
    - **是什么**：当多个不共享连续命名空间的树需要集成时，它们组成一个**森林**。例如，THM 公司的 `thm.local` 树和其收购的 MHT 公司的 `mht.inc` 树可以组成一个森林。
    - **优势**：允许不同组织在保持各自独立性的同时实现资源共享和协作。
- **信任关系 (Trusts)**：
    
    - **是什么**：为了让一个域中的用户能够访问另一个域中的资源，域之间必须建立**信任关系**。
    - **类型**：
        - **单向信任 (One-way Trust)**：如果域 A 信任域 B，则域 B 的用户可以被授权访问域 A 的资源（注意信任方向与访问方向相反）。
        - **双向信任 (Two-way Trust)**：两个域互相信任，允许彼此的用户相互授权访问资源。同一树或森林中的域之间默认建立双向可传递的信任关系。
    - **作用**：信任关系只是建立了授权的可能性，并不意味着自动授予任何权限。管理员仍需在资源上为来自受信任域的用户明确配置访问权限。