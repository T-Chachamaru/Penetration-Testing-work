#### 1. 物理安全 (Physical Security)

纵深防御的第一层是物理安全。如果攻击者能够物理接触到计算机，他们就可以轻易地移除硬盘或通过引导加载程序重置 root 密码。

> **核心原则**: “引导访问 = root 访问” (Boot Access = Root Access)

##### BIOS/UEFI 与 GRUB 密码

- **BIOS/UEFI 密码**: 可以在固件层面设置一个启动密码，阻止未经授权的用户启动系统。这适用于个人系统，但不适用于需要自动重启的服务器。
    
- **GRUB 密码**: 为 GRUB 引导加载程序添加密码，可以防止攻击者通过修改启动参数来获取 root shell。
    
    1. **生成密码哈希**:
        
        Bash
        
        ```
        grub2-mkpasswd-pbkdf2
        ```
        
    2. **配置**: 将生成的哈希值添加到相应的 GRUB 配置文件中。这会要求用户在尝试访问高级启动选项（如单用户模式）时输入密码。
        

#### 2. 文件系统分区与加密 (Filesystem Partitioning and Encryption)

加密可以确保即使硬盘被盗，其上的数据也无法被读取。

##### LUKS (Linux 统一密钥设置)

LUKS 是现代 Linux 发行版中用于全盘加密的标准。

- **工作原理**:
    
    1. 用户提供一个**密码 (passphrase)**。
        
    2. LUKS 使用 **PBKDF2** 算法，结合盐值和多次迭代，从该密码派生出一个**加密密钥 (Key)**。
        
    3. 这个加密密钥被用来加密一个**主密钥 (Master Key)**，并将加密后的主密钥存储在磁盘头的**密钥槽 (Key Slot)** 中。
        
    4. **主密钥**被用来加密磁盘上的所有**批量数据 (Bulk Data)**。
        
- **设置 LUKS 加密分区 (命令行示例)**:
    
    1. 安装工具: `sudo apt-get install cryptsetup`
        
    2. 识别分区: `lsblk` (假设目标分区为 `/dev/sdb1`)
        
    3. 格式化为 LUKS 分区: `sudo cryptsetup -y -v luksFormat /dev/sdb1`
        
    4. 打开加密分区并创建映射: `sudo cryptsetup luksOpen /dev/sdb1 EDCdrive`
        
    5. 格式化映射后的设备: `sudo mkfs.ext4 /dev/mapper/EDCdrive`
        
    6. 挂载并使用: `sudo mount /dev/mapper/EDCdrive /media/secure-USB`
        

#### 3. 防火墙 (Firewalls)

基于主机的防火墙是用于控制单个主机网络流量进出的软件。

##### Linux 防火墙技术栈

- **Netfilter**: 位于 Linux 内核中，是实际执行数据包过滤的核心框架。
    
- **iptables**: 传统的 netfilter 前端，通过链 (INPUT, OUTPUT, FORWARD) 来管理规则。
    
    - **示例 (允许 SSH 流量)**:
        
        Bash
        
        ```
        # 允许入站到端口 22 的流量
        sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        # 允许从端口 22 出站的流量
        sudo iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
        # 阻止所有其他流量
        sudo iptables -P INPUT DROP
        sudo iptables -P OUTPUT DROP
        ```
        
- **nftables**: 新一代的 netfilter 前端，在性能和语法上优于 `iptables`。
    
    - **示例 (允许 SSH 流量)**:
        
        Bash
        
        ```
        # 创建表和链
        sudo nft add table inet fwfilter
        sudo nft add chain inet fwfilter fwinput { type filter hook input priority 0 \; }
        sudo nft add chain inet fwfilter fwoutput { type filter hook output priority 0 \; }
        # 添加规则
        sudo nft add rule inet fwfilter fwinput tcp dport 22 accept
        sudo nft add rule inet fwfilter fwoutput tcp sport 22 accept
        ```
        
- **UFW (简易防火墙)**: `iptables` 的一个更简单的命令行前端，易于使用。
    
    - **示例 (允许 SSH 流量)**:
        
        Bash
        
        ```
        sudo ufw allow 22/tcp
        sudo ufw enable
        ```
        

#### 4. 远程访问安全 (Securing Remote Access)

##### 防范密码嗅探

- **禁用明文协议**: 始终使用 **SSH** 进行远程访问，禁用不加密的协议如 Telnet。
    

##### 防范密码猜测

- **禁用 root 登录**: 编辑 `/etc/ssh/sshd_config` 文件，确保以下设置：
    
    ```
    PermitRootLogin no
    ```
    
- **强制使用公钥认证**: 这是最安全的认证方法。
    
    1. **生成密钥对**: 在客户端上运行 `ssh-keygen -t rsa`。
        
    2. **复制公钥到服务器**: `ssh-copy-id username@server`。
        
    3. **禁用密码认证**: 在服务器的 `/etc/ssh/sshd_config` 中设置：
        
        ```
        PasswordAuthentication no
        PubkeyAuthentication yes
        ```
        

#### 5. 安全的用户账户管理 (Secure User Account Management)

##### 使用 `sudo`

避免直接使用 `root` 账户。应为管理员创建一个普通账户，并将其添加到 `sudo` (Debian/Ubuntu) 或 `wheel` (RedHat/Fedora) 组中。

Bash

```
# Debian/Ubuntu
sudo usermod -aG sudo username

# RedHat/Fedora
sudo usermod -aG wheel username
```

##### 禁用 `root` 账户

编辑 `/etc/passwd` 文件，将 `root` 用户的 shell 从 `/bin/bash` 更改为 `/sbin/nologin`。

##### 强制强密码策略

使用 `libpam-pwquality` 库（通过编辑 `/etc/security/pwquality.conf` 或 `/etc/pam.d/common-password`）来强制执行密码复杂性要求，如最小长度 (`minlen`)、字符类别 (`minclass`) 等。

##### 禁用未使用的账户

定期审查并禁用不再需要的用户账户和**服务账户**（如 `www-data`），方法是将其 shell 设置为 `/sbin/nologin`。

#### 6. 软件与服务安全 (Software and Service Security)

- **禁用不必要的服务**: 移除或禁用所有不需要的软件包和服务，以减少攻击面。
    
- **阻止不需要的网络端口**: 配置防火墙，只允许必要的服务端口对外开放。
    
- **避免使用过时协议**: 使用安全的替代方案（如用 SFTP 替代 TFTP）。
    
- **移除标识字符串**: 修改服务配置文件，移除或更改会暴露软件版本信息的 banner。
    

#### 7. 更新与升级策略 (Update and Upgrade Strategy)

保持系统和软件的最新状态是至关重要的安全措施。

- **更新命令**:
    
    - **Debian/Ubuntu**: `sudo apt update && sudo apt upgrade`
        
    - **RedHat/Fedora**: `sudo dnf update` 或 `sudo yum update`
        
- **LTS 与支持周期**: 优先使用长期支持 (LTS) 版本，并注意其支持生命周期，确保能持续接收安全更新。
    
- **内核更新的重要性**: 及时更新内核以修复严重漏洞，如著名的 “Dirty COW” (CVE-2016-5195)。
    

#### 8. 审计与日志配置 (Auditing and Log Configuration)

定期审查存储在 `/var/log` 目录下的日志文件是发现异常活动的关键。

- **重要日志文件**:
    
    - `/var/log/auth.log` 或 `/var/log/secure`: 身份验证日志。
        
    - `/var/log/messages`: 通用系统日志。
        
    - `/var/log/wtmp`: 用户登录/退出历史。
        

#### 9. Linux 加固实战 (Practical Linux Hardening Scenarios)

1. 问题: Redis 服务器无密码。
    
    修复: 编辑 redis.conf，取消注释 requirepass 并设置一个强密码。
    
2. 问题: 默认的 SNMP 社区名 (public/private)。
    
    修复: 编辑 snmpd.conf，将默认的社区名更改为复杂字符串。
    
3. 问题: Nginx 以 root 用户运行。
    
    修复: 编辑 nginx.conf，将 user 指令从 root 更改为 www-data 或其他非特权用户。
    
4. 问题: 启用 Telnet 等明文协议。
    
    修复: 编辑 inetd.conf 或相关配置文件，注释掉或移除 Telnet 服务，并强制使用 SSH。
    
5. 问题: SSH 支持弱的密钥交换(KEX)、加密或 MAC 算法。
    
    修复: 编辑 sshd_config，明确指定只使用强算法，移除所有已知的弱算法。
    
6. 问题: 启用匿名 FTP 登录。
    
    修复: 编辑 vsftpd.conf，将 anonymous_enable=YES 更改为 anonymous_enable=NO。
    
7. 问题: 暴露的数据库端口。
    
    修复: 编辑数据库配置文件（如 my.cnf），将 bind-address 设置为 127.0.0.1，使其只监听本地连接，并使用防火墙阻止外部访问。