## 概述 (Overview)

John the Ripper（简称 John）是一款著名且功能强大的开源密码破解工具。它旨在检测弱密码，支持破解数十种哈希类型（如 Linux shadow 文件、LM 哈希、MD5、SHA-1、Kerberos TGT 等），并能识别受密码保护的文件（如 ZIP、RAR、SSH 密钥）。它提供了多种攻击模式，适用于各种密码破解场景。

## 识别特征 / 使用场景 (Identification / Use Cases)

John 本身是一个审计和破解工具，通常在以下场景中使用：

1.  **密码安全审计：** 系统管理员使用 John 检测用户账户中是否存在弱密码。
2.  **渗透测试：** 在获取到密码哈希（例如从数据库 dump、shadow 文件、网络抓包等）后，尝试破解这些哈希以获取明文密码。
3.  **取证分析：** 从系统镜像或文件中提取哈希并进行破解。
4.  **文件密码恢复：** 破解受密码保护的 ZIP、RAR 压缩包或 SSH 私钥等文件的密码。
5.  **CTF 竞赛：** 解决涉及密码哈希破解的挑战。

当您拥有密码哈希或受密码保护的文件，并需要找出原始明文密码时，John 是一个核心工具。

## 工作原理 (Working Principle)

John 通过尝试不同的候选密码，计算其哈希值，并与目标哈希进行比较来工作。

1.  **输入哈希：** John 读取包含一个或多个待破解密码哈希的文件。这些哈希需要是 John 支持的格式。对于某些来源（如 shadow 文件、ZIP/RAR 文件），需要使用 `unshadow` 或 `*2john` 系列工具先提取出 John 可识别的哈希格式。
2.  **候选密码生成：** John 使用不同的攻击模式生成候选密码：
    *   **字典模式 (`--wordlist`)：** 从提供的单词列表（字典）中读取候选密码。
    *   **单一模式 (`--single`)：** 利用哈希文件中提供的额外信息（通常是用户名）生成候选密码的变体（例如，用户名为 "user1"，则尝试 "user1", "user123", "1resu" 等）。需要特定输入格式（`username:hash`）。
    *   **增量模式 (`--incremental`)：** 通过字符集暴力生成所有可能的密码组合（例如，尝试 "a", "b", ..., "aa", "ab", ...）。速度较慢但最全面。
    *   **规则模式 (`--rules`)：** 结合字典模式使用，对字典中的单词应用预定义的规则（如大小写转换、添加数字/符号、颠倒顺序等）来生成更复杂的候选密码。规则定义在 `john.conf` 文件中。
3.  **哈希计算与比较：** 对于每个生成的候选密码，John 使用目标哈希**相同**的算法（由 `--format` 指定或自动检测）计算其哈希值。
4.  **匹配与输出：** 如果计算出的哈希与目标哈希匹配，John 就认为找到了明文密码，并将其存储在 `john.pot` 文件中（potfile），同时通常会显示在屏幕上。使用 `--show` 选项可以查看已破解的密码。

**关键在于：** John 需要知道正确的哈希格式 (`--format`) 才能正确地计算和比较哈希值，并且需要有效的候选密码生成策略（攻击模式、字典、规则）才能高效地找到匹配项。

## 利用步骤 / 常用命令 (Exploitation Steps / Common Commands)

使用 John 破解密码通常遵循以下步骤：

1.  **获取哈希：** 从目标系统、数据库、文件等获取密码哈希或受保护文件。
2.  **格式转换 (如果需要)：** 使用 `unshadow`, `zip2john`, `rar2john`, `ssh2john` 等工具将原始数据转换为 John 可识别的哈希格式，并保存到文件中。
3.  **识别格式：** 确定哈希的具体类型（如 `raw-md5`, `sha512crypt`, `pkzip` 等）。可以使用 `john --list=formats` 查看支持的格式，或让 John 自动检测。
4.  **选择模式与资源：** 根据情况选择合适的攻击模式（字典、单一、增量、规则）和资源（如密码字典文件 `rockyou.txt`）。
5.  **执行破解：** 运行 John 命令。
6.  **查看结果：** 使用 `john --show` 命令查看已破解的密码。

**核心命令与参数 (Core Commands & Parameters):**

*   **基本格式:**
    ```bash
    john [选项] [哈希文件路径]
    ```
    *   `[选项]`: 指定攻击模式、格式、字典等。
    *   `[哈希文件路径]`: 包含待破解哈希的文件。可以是相对路径或绝对路径。

*   **攻击模式 (Attack Modes):**
    *   **字典模式 (`--wordlist`):**
        ```bash
        john --wordlist=<字典文件路径> <哈希文件路径>
        # 示例: 使用 rockyou.txt 字典
        john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
        ```
    *   **单一模式 (`--single`):** （需要 `用户名:哈希` 格式的输入文件）
        ```bash
        # 假设 hashes.txt 内容为 "mike:1efee03cdcb96d90ad48ccc7b8666033"
        john --single --format=raw-md5 hashes.txt
        ```
    *   **增量模式 (`--incremental`):** (通常指定字符集，如 `--incremental=Digits` 只尝试数字)
        ```bash
        john --incremental <哈希文件路径>
        ```
    *   **规则模式 (`--rules`):** (通常与字典模式结合)
        ```bash
        # 使用 john.conf 中定义的 "Custom" 规则集
        john --wordlist=<字典文件路径> --rules=Custom <哈希文件路径>
        ```

*   **指定哈希格式 (`--format`):**
    ```bash
    john --format=<格式名称> --wordlist=<字典路径> <哈希文件路径>
    # 示例: 指定 raw-sha256 格式
    john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
    ```
    *   如果格式指定错误，John 会报错。不指定时，John 会尝试自动检测。

*   **文件预处理工具 (`*2john`):**
    *   **Unix 密码文件 (`unshadow`):**
        ```bash
        unshadow /etc/passwd /etc/shadow > unshadowed.txt
        john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
        ```
    *   **ZIP 文件 (`zip2john`):**
        ```bash
        zip2john protected.zip > zip_hash.txt
        john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
        ```
    *   **RAR 文件 (`rar2john`):**
        ```bash
        rar2john protected.rar > rar_hash.txt
        john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
        ```
    *   **SSH 密钥 (`ssh2john`):**
        ```bash
        ssh2john id_rsa > id_rsa_hash.txt
        john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
        ```

*   **自定义规则 (Custom Rules):**
    *   编辑 `john.conf` (通常在 `/etc/john/john.conf` 或 John 安装目录下)，在 `[List.Rules:RuleName]` 部分添加规则。
    *   **示例规则 (添加到 `[List.Rules:Custom]`):** `Az"[0-9][0-9][0-9]a[!@#$*]"` (在单词末尾追加 3 个数字、1 个小写字母和 1 个指定符号)
    *   **使用自定义规则:**
        ```bash
        john --rules=Custom --wordlist=<字典路径> <哈希文件路径>
        ```

*   **实用技巧 (Practical Tips):**
    *   **查看已破解密码:**
        ```bash
        john --show <哈希文件路径>
        ```
    *   **列出支持的格式:**
        ```bash
        john --list=formats
        ```
    *   **恢复中断的会话:**
        ```bash
        john --restore
        ```