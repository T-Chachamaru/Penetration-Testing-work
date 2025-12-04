#### 概述
Web Fuzzing 是一种通过向 Web 应用程序发送大量、自动生成的请求来探测隐藏内容、目录、参数或有效凭证（如用户名、密码）的技术。`ffuf` 是一款常用的高速 Web Fuzzing 工具。

#### 方法

1.  **用户名枚举 (基于响应特征)**
    *   **目的**: 通过探测注册或登录接口，根据服务器对不同用户名的响应差异（例如特定错误信息），来识别系统中存在的有效用户名。
    *   **工具**: `ffuf`
    *   **示例命令**:
        ```bash
        ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.94.202/customers/signup -mr "username already exists"
        ```
    *   **参数说明**:
        *   `-w /path/to/wordlist.txt`: 指定用于替换 `FUZZ` 关键字的字典文件路径（此处为用户名列表）。
        *   `-X POST`: 指定 HTTP 请求方法为 POST。
        *   `-d "..."`: 指定 POST 请求的数据体。`FUZZ` 关键字会被字典中的每个词替换。
        *   `-H "Header: Value"`: 添加额外的 HTTP 请求头（此处指定内容类型）。
        *   `-u URL`: 指定目标 URL。
        *   `-mr "text"`: 匹配响应体中的特定文本。只有包含 "username already exists" 的响应才会被显示，这表明字典中的某个词是一个已存在的用户名。

2.  **密码爆破 (基于已知用户名)**
    *   **目的**: 在已知有效用户名的前提下，尝试使用常用密码列表来破解用户密码。
    *   **工具**: `ffuf`
    *   **示例命令**:
        ```bash
        ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.94.202/customers/login -fc 200
        ```
    *   **参数说明**:
        *   `-w wordlist1:W1,wordlist2:W2`: 指定多个字典文件，并为它们分配关键字 `W1` 和 `W2`。`W1` 对应 `valid_usernames.txt`（有效用户名列表），`W2` 对应密码列表。
        *   `-X POST`: 指定 HTTP 请求方法为 POST。
        *   `-d "username=W1&password=W2"`: 指定 POST 请求数据体。`W1` 会被用户名列表中的词替换，`W2` 会被密码列表中的词替换，`ffuf` 会尝试所有组合。
        *   `-H "Header: Value"`: 添加额外的 HTTP 请求头。
        *   `-u URL`: 指定目标 URL（登录接口）。
        *   `-fc 200`: 过滤掉 HTTP 状态码为 200 的响应。这通常用于隐藏登录失败的响应（假设失败返回 200），以便更容易发现指示成功的不同状态码（如 302 跳转）。