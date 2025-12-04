#### 操作系统与账户信息 (Operating System & Account Information)

##### 1. 操作系统版本 (Operating System Version)

要查找操作系统版本信息，可以使用 `cat` 工具读取 `/etc/os-release` 文件。

Bash

```
cat /etc/os-release
```

##### 2. 用户账户 (`/etc/passwd`)

`/etc/passwd` 文件包含系统上所有用户账户的信息。输出包含 7 个以冒号分隔的字段：用户名、密码信息、用户 ID (UID)、组 ID (GID)、描述、主目录和默认 Shell。

- **普通用户 UID**: 通常为 `1000` 或更高。
    
- **格式化查看**:
    
    Bash
    
    ```
    cat /etc/passwd | column -t -s :
    ```
    

##### 3. 组信息 (`/etc/group`)

`/etc/group` 文件包含主机上所有用户组的信息，可使用 `cat` 工具读取。

##### 4. Sudoers 列表 (`/etc/sudoers`)

此文件定义了哪些用户可以使用 `sudo` 提升权限。需要提升权限才能读取此文件。

Bash

```
sudo cat /etc/sudoers
```

##### 5. 登录信息 (`wtmp`, `btmp`)

这些二进制日志文件位于 `/var/log/` 目录，需要使用 `last` 工具读取。

- **`wtmp`**: 记录了成功的登录历史。
    
- **`btmp`**: 记录了失败的登录尝试。
    
- **查看命令**:
    
    Bash
    
    ```
    # 查看成功登录历史
    sudo last -f /var/log/wtmp
    
    # 查看失败登录尝试 (lastb 是 last -f /var/log/btmp 的快捷方式)
    sudo lastb
    ```
    

##### 6. 认证日志 (`auth.log`)

记录了所有用户的身份验证活动，位于 `/var/log/auth.log`。由于文件较大，建议使用 `tail`、`less` 等工具查看。

#### 系统配置 (System Configuration)

##### 1. 主机名 (Hostname)

主机名存储在 `/etc/hostname` 文件中。

Bash

```
cat /etc/hostname
```

##### 2. 时区 (Timezone)

时区信息位于 `/etc/timezone`，它为设备的大致位置提供了线索。

##### 3. 网络配置 (Network Configuration)

- **接口配置**: `/etc/network/interfaces` 文件包含网络接口的静态配置。
    
- **IP 与 MAC 地址**: 使用 `ip` 工具查看当前活动的接口信息。
    
    Bash
    
    ```
    ip address show
    ```
    

##### 4. 活动网络连接 (Active Network Connections)

使用 `netstat` 工具查看当前系统上的活动网络连接。

Bash

```
netstat -natp
```

##### 5. 运行中进程 (Running Processes)

使用 `ps` 工具查看当前正在运行的进程的详细信息。

Bash

```
ps aux
```

##### 6. DNS 信息 (DNS Information)

- **Hosts 文件**: `/etc/hosts` 文件包含本地 DNS 名称到 IP 地址的映射。
    
- **DNS 服务器**: `/etc/resolv.conf` 文件定义了系统用于 DNS 解析的服务器地址。
    

#### 持久化机制 (Persistence Mechanisms)

##### 1. 定时任务 (Cron Jobs)

计划任务（Cron jobs）是按预设时间间隔定期运行的命令。系统级的计划任务列表位于 `/etc/crontab` 文件中。

##### 2. 服务启动 (Startup Services)

与 Windows 服务类似，Linux 服务可以在系统启动时自动运行。这些服务的脚本通常位于 `/etc/init.d/` 目录中。

##### 3. Bash 配置文件 (`.bashrc`)

当 Bash Shell 启动时，它会执行 `.bashrc` 文件中的命令，攻击者可能在此处添加恶意命令以实现持久化。

- **用户级**: `~/.bashrc`
    
- **系统级**: `/etc/bash.bashrc` 和 `/etc/profile`
    

#### 执行证据 (Execution Evidence)

##### 1. Sudo 执行历史 (Sudo Execution History)

所有使用 `sudo` 执行的命令都会被记录在**认证日志** (`/var/log/auth.log`) 中。

##### 2. Bash 历史 (`.bash_history`)

除 `sudo` 命令外，用户在终端中执行的命令都存储在各自的 `.bash_history` 文件中。

- **位置**: 每个用户的主目录下 (`~/.bash_history`)。
    
- **重要性**: 检查每个用户（包括 `root` 用户）的 `bash` 历史至关重要。
    

##### 3. Vim 使用历史 (`.viminfo`)

Vim 文本编辑器会将其使用历史记录在 `~/.viminfo` 文件中，包括打开文件的历史、搜索字符串等。

#### 文件系统取证 (File System Forensics)

##### 1. 文件所有权与权限 (File Ownership and Permissions)

攻击者常利用具有写权限的目录来上传恶意文件。

- **常见的全局可写目录**: `/tmp`, `/var/tmp`, `/dev/shm`
    
- **检查命令**:
    
    Bash
    
    ```
    # 查找特定组拥有的文件
    find / -group GROUPNAME 2>/dev/null
    
    # 查找所有全局可写的文件和目录
    find / -perm -o+w 2>/dev/null
    
    # 查找过去5分钟内创建或更改的文件
    find / -type f -cmin -5 2>/dev/null
    ```
    

##### 2. 元数据分析 (Metadata Analysis)

元数据是描述文件的内嵌信息（创建日期、作者等）。**Exiftool** 是一款强大的命令行工具，可用于提取和分析文件的元数据。

##### 3. 校验和分析 (Checksum Analysis)

校验和用于验证文件完整性，并可提交至 VirusTotal 等平台识别已知恶意文件。

- **常用工具**: `md5sum` 和 `sha256sum`。
    

##### 4. 时间戳分析 (Timestamp Analysis)

时间戳是建立事件时间线的关键。

- **三种主要时间戳**:
    
    - **`mtime` (修改时间)**: 文件**内容**最后一次被修改的时间。
        
    - **`ctime` (更改时间)**: 文件**元数据**（如权限、所有权）最后一次被更改的时间。
        
    - **`atime` (访问时间)**: 文件最后一次被访问或读取的时间。
        
- **查看工具**: `stat` 命令可以一次性查看文件的所有三个时间戳。
    

> **注意**：在实时取证分析中，`atime` 极易被调查行为（如 `cat`、`md5sum`）所改变，因此它不是一个可靠的指标。这也是为什么取证前制作镜像是首选方案。

#### 用户与组深度分析 (In-Depth User and Group Analysis)

##### 1. 识别后门用户 (Identifying Backdoor Users)

攻击者可能创建 UID 为 `0`（与 `root` 相同）的后门账户。

Bash

```
# 查找所有 UID 为 0 的账户
cat /etc/passwd | cut -d: -f1,3 | grep ':0$'
```

##### 2. 识别可疑组成员 (Identifying Suspicious Group Memberships)

攻击者可能会将用户添加到高权限组以提升权限。

- **高风险组**:
    
    - **`sudo` 或 `wheel`**: 允许使用 `sudo` 执行命令。
        
    - **`adm`**: 通常拥有读取系统日志的权限。
        
    - **`shadow`**: 可读取包含密码哈希的 `/etc/shadow` 文件。
        
    - **`disk`**: 拥有广泛的磁盘读写权限。
        
- **检查命令**:
    
    Bash
    
    ```
    # 查看用户所属的组
    groups <username>
    
    # 查看特定组的所有成员
    getent group <groupname>
    ```
    

##### 3. 用户登录与活动分析 (Analyzing User Login and Activity)

- **`last`**: 读取 `/var/log/wtmp`，显示最近的登录历史。
    
- **`lastb`**: 读取 `/var/log/btmp`，显示失败的登录尝试。
    
- **`lastlog`**: 读取 `/var/log/lastlog`，显示所有用户最后一次的登录信息。
    
- **`who`**: 显示当前正登录到系统的用户。
    

#### 用户目录与文件审查 (User Directory and File Review)

用户主目录（通常在 `/home`）包含大量个人配置和数据。

- **隐藏文件**: 以 `.` 开头的文件（使用 `ls -a` 查看）通常包含敏感配置。
    
    - **`.bash_history`**: 命令历史。
        
    - **`.bashrc`, `.profile`**: Shell 配置文件。
        
- **SSH 与后门**:
    
    - `~/.ssh` 目录包含 SSH 密钥和配置。
        
    - 攻击者可能将自己的公钥添加到 `~/.ssh/authorized_keys` 文件中，以创建无密码登录的持久化后门。
        

#### 二进制文件与可执行文件分析 (Binary and Executable Analysis)

##### 1. 字符串提取 (String Extraction)

`strings` 命令可以从二进制文件中提取可读的文本字符串，有助于理解其功能。

##### 2. 软件包完整性验证 (Package Integrity Verification)

在基于 Debian 的系统上，`debsums` 工具可以将已安装软件包文件的 MD5 校验和与官方元数据进行比较，以检测恶意篡改。

Bash

```
sudo debsums -e -s
```

##### 3. 特殊权限分析 (Special Permissions Analysis)

**SUID (SetUID)** 和 **SGID (SetGID)** 是特殊的权限位，允许用户在执行文件时临时获得文件所有者或组的权限。如果配置不当，攻击者可利用带有 SUID 位的程序进行提权。

- **查找 SUID 文件**:
    
    Bash
    
    ```
    find / -perm -u=s -type f 2>/dev/null
    ```
    

#### Rootkit 检测 (Rootkit Detection)

**Rootkit** 是一种旨在隐藏自身及其他恶意软件踪迹的工具集，以获取并维持对系统的 root 级控制。

- **检测工具**:
    
    - **`chkrootkit`**: 一个轻量级的 shell 脚本，通过签名扫描来快速识别已知的 rootkit。
        
    - **`rkhunter` (Rootkit Hunter)**: 功能更全面的工具，通过哈希比对、检查文件权限、内核模块等方式进行更深入的检测。建议在运行前使用 `rkhunter --update` 更新其签名数据库。