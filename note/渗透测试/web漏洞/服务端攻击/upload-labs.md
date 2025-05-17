## 概述 (Overview)

文件上传功能是Web应用程序的常见部分，但如果实现不当，极易引入安全漏洞。攻击者可能上传恶意文件（如WebShell）来执行任意代码、控制服务器或进行其他恶意活动。`upload-labs`是一个专注于文件上传漏洞的靶场，以下是一些常见的绕过技巧和利用方法总结。

## 上传检查与绕过 (Upload Checks and Bypasses)

### 客户端检查 (Client-Side Checks)

*   **类型**: 通常使用 JavaScript 在浏览器端检查文件后缀名或 `MIME` 类型。
*   **绕过**: 非常容易绕过。可以通过以下方式：
    1.  禁用浏览器 JavaScript。
    2.  使用抓包工具（如 Burp Suite）拦截并修改上传请求（文件名、后缀、`Content-Type`）。
*   **结论**: 客户端检查只能提供基本的用户体验，不能作为安全措施。

### 服务端检查 (Server-Side Checks)

当文件上传请求到达后端服务器时，会进行更严格的检查。

#### 1. MIME 类型检查绕过 (MIME Type Bypass)

*   **原理**: 服务器检查 HTTP 请求头中的 `Content-Type` 字段来判断文件类型。
*   **绕过**: 使用抓包工具修改请求，将恶意脚本（如 `shell.php`）的 `Content-Type` 修改为允许的类型（如 `image/jpeg`, `image/png`）。

#### 2. 文件名/后缀检查绕过 (Filename/Extension Bypass)

服务器通常会根据文件名后缀来判断是否允许上传，分为黑名单和白名单策略。

##### 黑名单策略绕过 (Blacklist Bypass)

黑名单禁止上传特定后缀（如 `.php`, `.asp`）。绕过方法较多：

*   **修改后缀**:
    *   **大小写绕过**: 尝试使用 `.pHp`, `.PhP`, `.php` 等混合大小写（主要针对 Windows 服务器，Linux 默认区分大小写）。
    *   **特殊可解析后缀**: 尝试上传 `.php3`, `.php5`, `.phtml`, `.pht` 等可能被 Apache/PHP 解析为 PHP 脚本的后缀。
    *   **末尾添加特殊字符**:
        *   **空格**: 尝试在后缀后添加空格 (`shell.php `) - Windows 会自动去除文件名末尾的空格。
        *   **点**: 尝试在后缀后添加点 (`shell.php.`) - Windows 会自动去除文件名末尾的点。
        *   **点+空格+点**: 尝试 (`shell.php. .`) 等组合。
    *   **::$DATA (Windows)**: 尝试 `shell.php::$DATA`。这是 Windows NTFS 文件系统的一个特性（ADS - Alternate Data Stream）。上传时，某些服务器配置下可能只检查 `shell.php` 部分，但文件内容会写入到主文件流中，从而绕过检测。

*   **`.htaccess` 文件**:
    *   **原理**: `.htaccess` 是 Apache 服务器的分布式配置文件。如果在配置中启用了 `AllowOverride`，可以在特定目录下放置 `.htaccess` 文件来改变该目录及其子目录的服务器行为。
    *   **利用**: 上传一个名为 `.htaccess` 的文件，内容如下，指示 Apache 将指定类型的文件（甚至所有文件）当作 PHP 来解析：
        ```htaccess
        # 将 .jpg 文件当作 php 解析
        AddType application/x-httpd-php .jpg

        # 或者，强制目录下所有文件都以 PHP 解析 (更强力，但也可能破坏正常功能)
        # SetHandler application/x-httpd-php
        ```
    *   **步骤**: 先上传配置好的 `.htaccess` 文件，然后上传一个符合规则（如 `webshell.jpg`）但内容是 PHP 代码的图片马。

*   **`.user.ini` 文件 (PHP)**:
    *   **原理**: 自 PHP 5.3.0 起，在 CGI/FastCGI 模式下，PHP 会在执行脚本前扫描其所在目录及上级目录（直至 Web 根目录）是否存在名为 `.user.ini` (可通过 `user_ini.filename` 配置) 的文件，并将其中的配置指令应用于该目录。
    *   **前提**: 服务器使用 CGI/FastCGI 模式运行 PHP；上传目录下有可被执行的 PHP 文件（即使是正常的业务文件）；允许上传 `.ini` 文件或能绕过后缀检查上传 `.user.ini`。
    *   **利用**: 上传一个名为 `.user.ini` 的文件，内容利用 `auto_prepend_file` 或 `auto_append_file` 指令来自动包含上传的 Webshell 文件（例如一个图片马 `webshell.jpg`）。
        ```ini
        ; .user.ini
        auto_prepend_file=webshell.jpg
        ```
    *   **步骤**: 先上传包含 PHP 代码的 `webshell.jpg`，再上传 `.user.ini` 文件。当该目录下的任何 `.php` 文件被访问时，`webshell.jpg` 中的代码会首先被执行。（注意：配置有缓存时间 `user_ini.cache_ttl`，默认为 300 秒）。

*   **特殊符号绕过 (Windows)**:
    *   **冒号截断/流特性**: 在 Windows 中，文件名后的冒号 `:` 有特殊含义。尝试上传 `shell.php:.jpg`。在某些旧系统或特定处理方式下，保存文件时可能会忽略冒号后的部分，或者将其视为文件流标识符。
    *   **结合 `move_uploaded_file` 特性**: 有时可以结合 `move_uploaded_file` 函数对路径的处理特性（如忽略末尾的点、斜杠）或与其他漏洞（如目录穿越）一起利用。 *（注意：这种方法较为特定，依赖具体实现和环境）*

*   **双写绕过**: 如果后端代码使用 `str_replace` 等函数只替换一次过滤字符，可以尝试双写。例如，如果过滤 `php`，尝试上传 `phphpp`，替换后可能剩下 `php`。

##### 白名单策略绕过 (Whitelist Bypass)

白名单只允许上传特定后缀（如 `.jpg`, `.png`, `.gif`）。绕过难度通常更大。

*   **0x00 截断**:
    *   **原理**: 在 C 语言等底层实现中，`0x00` (空字节) 被视为字符串结束符。如果 PHP 版本较低 ( < 5.3.4 ) 且 `move_uploaded_file` 或类似文件处理函数的路径参数可控，可以利用此特性。
    *   **利用 (GET 参数)**: 假设保存路径由 GET 参数 `path` 控制，可以构造 URL：`/upload.php?path=../upload/shell.php%00`，同时上传一个正常后缀的文件（如 `legit.jpg`）。如果后端拼接路径为 `$path . $filename`，则实际保存路径会因 `%00` 截断变为 `../upload/shell.php`。
    *   **利用 (POST 参数)**: 如果路径在 POST 数据中，需要使用 Burp Suite 等工具，在 Hex 编辑器中将 `%00` 对应的 URL 编码改为真正的 `00` 字节。
    *   **注意**: 此漏洞在较新 PHP 版本中已被修复。

*   **路径处理特性 (`move_uploaded_file`)**:
    *   **末尾 `/` 或 `/.`**: 在某些低版本 PHP 和特定操作系统组合下，`move_uploaded_file` 函数可能会忽略路径末尾的 `/` 或 `/.`。可以构造保存路径为 `/upload/shell.php/.`，并上传 `legit.jpg`，最终可能保存为 `/upload/shell.php`。
    *   **注意**: 这同样是较老版本的漏洞。

#### 3. 内容检查绕过 (Content Check Bypass)

服务器可能读取文件内容进行检查，例如检查文件头、调用图像处理函数等。

*   **图片马 (Image Webshell)**:
    *   **原理**: 将 PHP 代码隐藏在合法的图片文件中。
    *   **制作**:
        *   **手动添加**: 在合法图片文件的二进制内容中（例如末尾或不影响图像显示的区域）插入 PHP 代码 (`<?php ... ?>`)。
        *   **伪造文件头**: 在 PHP 脚本内容前添加真实的图片文件头签名：
            *   **GIF**: `GIF89a` (Hex: `47 49 46 38 39 61`)
            *   **PNG**: `.PNG` (Hex: `89 50 4E 47 0D 0A 1A 0A`)
            *   **JPG**: `ÿØ` (Hex: `FF D8`)
        *   **命令行合并 (Windows)**: `copy /b image.png + shell.php webshell.png` (二进制合并)
    *   **利用**: 上传制作好的图片马。如果服务器只检查文件头或简单地验证是否为图片，上传会成功。然后需要配合其他漏洞（如 **文件包含 (LFI)**）来执行图片马中的代码：`include.php?file=uploads/webshell.png`。

*   **二次渲染绕过 (Secondary Rendering Bypass)**:
    *   **原理**: 一些网站会对上传的图片进行二次处理（如缩放、裁剪、加水印），这个过程会重新生成图片，可能破坏插入的 Webshell 代码。
    *   **绕过**:
        1.  上传一个包含特殊标记（或简单 Webshell）的图片。
        2.  下载服务器处理后的图片。
        3.  使用二进制对比工具（如 Beyond Compare 或 `hexedit`）比较原始图片和渲染后的图片，找到渲染过程中未被修改或变化有规律的部分。
        4.  将 Webshell 代码精确地插入到这些“稳定”的位置。
        5.  重新上传修改后的图片马。

## 逻辑漏洞利用 (Exploiting Logic Flaws)

### 条件竞争 (Race Condition)

*   **原理**: 如果服务器的处理逻辑是“先上传保存文件 -> 再进行检查/处理 -> 如果不合法则删除”，那么在“保存文件”和“删除文件”之间存在一个短暂的时间窗口。
*   **利用**:
    1.  准备一个上传请求，上传一个“探针”Webshell，其功能是：一旦被访问，就在同目录下生成一个更持久的 Webshell（例如 `shell.php`）。
        ```php
        // probe.php - a file to be uploaded repeatedly
        <?php fputs(fopen('shell.php','w'),'<?php @eval($_POST["cmd"]);?>');?>
        ```
    2.  使用多线程脚本：
        *   一个线程不断地发送上传请求，上传 `probe.php`。
        *   另一个（或多个）线程不断地访问 `probe.php` 可能存在的 URL (`http://target.com/uploads/probe.php`)。
    3.  如果在 `probe.php` 被删除前成功访问了它，它就会执行 `fputs`，创建 `shell.php`。由于 `shell.php` 不是直接上传的文件，它可能不会被后续的删除逻辑处理掉。
    4.  持续尝试，直到发现 `shell.php` 成功创建并可以访问。
*   **配合**: 条件竞争也可以与其他技术结合，例如先利用条件竞争上传一个 `.htaccess` 或 `.user.ini` 文件，再上传图片马。

### 数组类型绕过 (Array Type Bypass)

*   **原理**: 如果后端代码期望接收一个字符串类型的参数（例如文件名或路径），但接收到了一个数组类型，处理不当时可能会导致预期外的行为或绕过某些检查。例如，使用 `explode()`、`substr()`、`strrpos()` 等函数处理文件名时，如果传入数组可能会报错或返回 `NULL`，从而跳过检查。
*   **利用**: 在 Burp Suite 等工具中，修改 POST 请求参数，将某个参数（如 `filename="shell.php"`）修改为数组形式（如 `filename[]="shell.php"`）。
*   **影响**: 具体效果取决于后端代码逻辑。可能导致绕过后缀检查、路径拼接错误、或触发其他未预料的处理流程，最终可能形成 Webshell。