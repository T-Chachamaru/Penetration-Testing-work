#### 1. 基础用法 (Basic Usage)

`ffuf` (Fuzz Faster U Fool) 是一款功能强大的命令行 Web Fuzzer。其基础用法需要提供两个核心参数：

- `-u`: 指定目标 URL。
    
- `-w`: 指定用于 Fuzzing 的单词列表。
    

默认情况下，`ffuf` 会将单词列表中的每一行替换掉 URL 中的 `FUZZ` 关键词。

Bash

```
ffuf -u http://10.10.227.211/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt
```

##### 自定义关键词 (Custom Keywords)

你也可以使用自定义关键词代替 `FUZZ`，只需在指定单词列表时用冒号分隔即可：`wordlist.txt:KEYWORD`。

Bash

```
ffuf -u http://10.10.227.211/NORAJ -w /usr/share/seclists/Discovery/Web-Content/big.txt:NORAJ
```

#### 2. 目录与文件发现 (Directory and File Discovery)

##### 扩展名枚举 (Extension Enumeration)

通过 Fuzzing 文件扩展名，可以快速确定 Web 应用程序使用的后端技术。

Bash

```
# 将 FUZZ 放在已知文件名之后，用于测试不同的扩展名
ffuf -u http://10.10.227.211/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```

##### 文件枚举与扩展名追加 (File Enumeration with Extension Appending)

找到支持的扩展名后，可以使用 `-e` 参数将其自动追加到单词列表的每个词条后面。

Bash

```
# Fuzz 文件名，并自动追加 .php 和 .txt 扩展名
ffuf -u http://10.10.227.211/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .php,.txt
```

##### 目录枚举 (Directory Enumeration)

Fuzzing 目录是 Web 侦察的常见起点。

Bash

```
ffuf -u http://10.10.227.211/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
```

#### 3. 过滤结果 (Filtering Results)

`ffuf` 的输出可能会非常嘈杂，使用过滤器来精确地显示或隐藏结果至关重要。

##### 按状态码过滤 (Filtering by Status Code)

- **`-fc` (Filter Code)**: **隐藏**指定的状态码。
    
    Bash
    
    ```
    # 隐藏所有 403 Forbidden 的响应
    ffuf -u http://10.10.227.211/FUZZ -w /path/to/wordlist.txt -fc 403
    ```
    
- **`-mc` (Match Code)**: **只显示**指定的状态码。
    
    Bash
    
    ```
    # 只显示所有 200 OK 的响应
    ffuf -u http://10.10.227.211/FUZZ -w /path/to/wordlist.txt -mc 200
    ```
    

##### 按响应大小过滤 (Filtering by Response Size)

- **`-fs` (Filter Size)**: **隐藏**指定大小的响应。这对于过滤掉内容为空或只包含通用错误消息的页面非常有用。
    
    Bash
    
    ```
    # 隐藏所有响应大小为 0 字节的页面
    ffuf -u http://10.10.227.211/FUZZ -w /path/to/wordlist.txt -fs 0
    ```
    

##### 按正则表达式过滤 (Filtering by Regular Expression)

- **`-fr` (Filter Regex)**: **隐藏**与指定正则表达式匹配的响应内容。
    
    Bash
    
    ```
    # 隐藏所有以点(.)开头的路径，以过滤掉常见的 .htaccess 等误报
    ffuf -u http://10.10.227.211/FUZZ -w /path/to/wordlist.txt -fr '/\..*'
    ```
    

#### 4. Fuzzing 参数与数据 (Fuzzing Parameters and Data)

##### 参数模糊测试 (Fuzzing Parameters)

将 `FUZZ` 关键词放置在 URL 的参数部分，可以用于发现隐藏的或未记录的 GET 参数。

Bash

```
ffuf -u 'http://10.10.227.211/page.php?FUZZ=1' -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt
```

##### 从 STDIN 读取单词列表 (Reading Wordlists from STDIN)

使用 `-w -` 参数，`ffuf` 可以从标准输入 (stdin) 读取单词列表，这使得它可以与 `seq`, `ruby`, `for` 循环等命令结合，动态生成 payload。

Bash

```
# 使用 seq 生成 0 到 255 的数字列表，并将其通过管道传递给 ffuf
seq 0 255 | ffuf -u 'http://10.10.227.211/sqli-labs/Less-1/?id=FUZZ' -c -w -
```

##### POST 数据模糊测试 (暴力破解)

`ffuf` 也可用于对登录表单等进行暴力破解攻击。

- **关键参数**:
    
    - `-X POST`: 指定请求方法为 POST。
        
    - `-d 'data'`: 提供 POST 请求的正文数据，将 `FUZZ` 放置在需要爆破的字段（如密码）。
        
    - `-H 'Header: value'`: 添加或修改 HTTP 请求头，对于 POST 请求，`Content-Type` 头通常是必需的。
        
    - `-fs <size>`: 过滤掉登录失败时返回的、大小固定的响应页面。
        
- **示例命令**:
    
    Bash
    
    ```
    ffuf -u http://10.10.227.211/login.php \
    -w /usr/share/seclists/Passwords/Leaked-Databases/hak5.txt \
    -X POST \
    -d 'uname=Dummy&passwd=FUZZ&submit=Submit' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -fs 1435
    ```
    

#### 5. 子域名枚举 (Subdomain Enumeration)

##### 直接子域名枚举 (Direct Subdomain Enumeration)

将 `FUZZ` 关键词放置在 URL 的子域名部分。

Bash

```
ffuf -u http://FUZZ.mydomain.com -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

##### 虚拟主机 (vhost) 枚举 (Virtual Host (vhost) Enumeration)

有些子域名可能不存在于公共 DNS 中，而是通过 Web 服务器的虚拟主机配置实现的。我们可以通过 Fuzzing `Host` HTTP 头来发现它们。

Bash

```
ffuf -u http://mydomain.com -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.mydomain.com'
```

#### 6. 使用代理 (Using a Proxy)

##### 代理所有流量 (Proxying All Traffic)

使用 `-x` 参数，可以将 `ffuf` 的所有请求都通过一个代理（如 Burp Suite）发送。

Bash

```
ffuf -u http://10.10.227.211/FUZZ -c -w /path/to/wordlist.txt -x http://127.0.0.1:8080
```

##### 仅代理匹配项 (Proxying Only Matches)

使用 `-replay-proxy` 参数，只有**匹配**了过滤条件（例如，返回 `200 OK`）的请求才会被发送到代理。这对于减少代理历史记录中的噪音非常有用。

Bash

```
ffuf -u http://10.10.227.211/FUZZ -c -w /path/to/wordlist.txt -mc 200 -replay-proxy http://127.0.0.1:8080
```