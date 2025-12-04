### 一、 概述 (Overview) - 什么是 CSRF？

CSRF (Cross-Site Request Forgery)，即跨站请求伪造，是一种常见的、具有欺骗性的 Web 安全漏洞。它允许攻击者诱导一个已通过身份验证（例如已登录）的用户，在用户毫不知情的情况下，向其当前已认证的受信任网站发送一个恶意的、非预期的请求。

这种攻击的核心在于利用了以下两点：

1.  **浏览器的 Cookie 自动发送机制**: Web 浏览器在向某个域名发送请求时，会自动携带该域名下存储的所有相关 Cookie（或其他身份验证凭证，如 HTTP Basic Auth）。
2.  **服务器端的信任**: Web 应用程序通常仅依赖 Cookie（或其他会话凭证）来验证用户身份，而无法轻易区分请求是用户真实意愿发起的，还是由第三方网站伪造的。

攻击者通过构造一个指向目标网站操作的恶意 URL 或表单，并诱使用户（受害者）在已登录目标网站的状态下，通过浏览器访问这个恶意构造（例如点击恶意链接、访问包含恶意代码的页面），用户的浏览器就会自动携带有效的身份凭证去执行攻击者指定的操作。

### 二、 CSRF 攻击周期与流程 (Attack Cycle and Flow)

CSRF 攻击通常遵循以下基本阶段/流程：

1.  **受害者登录**: 用户（受害者 C）首先登录受信任的目标网站 A，并在浏览器中保留了有效的会话凭证（如 Session Cookie）。
2.  **攻击者构造恶意载体**: 攻击者预先了解目标网站 A 上某个操作（如转账、修改密码、发帖）的请求格式，并构造一个能够触发该操作的恶意链接、图片、表单或脚本。
3.  **诱导受害者触发**: 攻击者通过各种手段（如钓鱼邮件、恶意广告、论坛帖子、社交媒体消息）诱导受害者 C，在保持网站 A 登录状态的同一个浏览器中，访问包含恶意载体的页面或点击恶意链接。这种交互可能是一个简单的点击、鼠标悬停，甚至是页面加载时自动触发。
4.  **浏览器发送伪造请求**: 当受害者的浏览器尝试加载或执行恶意载体中的内容时（如加载图片 `src` 指向的 URL，或自动提交一个隐藏表单），浏览器会自动将与目标网站 A 关联的有效 Cookie 附加到这个伪造的请求中。
5.  **服务器处理请求**: 目标网站 A 收到请求。由于请求中包含了合法的用户凭证 Cookie，且缺乏有效的 CSRF 防御措施，网站 A 无法区分这是用户主动发起的合法请求还是由第三方伪造的恶意请求。因此，网站 A 会根据受害者 C 的权限处理该请求。
6.  **攻击成功**: 如果请求是执行某个状态改变的操作（如修改密码、转账、删除文章），并且受害者 C 拥有执行该操作的权限，那么这个恶意操作就会在用户不知情的情况下被成功执行。

**两个关键侧重点:**

*   CSRF 攻击建立在浏览器与目标 Web 服务器的 **有效会话** 之上。
*   攻击者通过 **欺骗用户访问** 特制的 URL 或页面，间接利用用户的身份发起请求。

### 三、 危害与影响 (Impact and Risks)

理解 CSRF 的影响对于维护在线活动安全至关重要。虽然 CSRF 攻击通常不直接暴露用户数据（不像 XSS 可能窃取 Cookie），但它们仍然可以通过 **以用户的名义执行未授权的操作** 来造成严重损害。相关风险和危害包括：

*   **未授权的操作与访问**: 攻击者可以利用受害者的身份执行任何该用户权限范围内的操作，例如：
    *   **修改账户信息**: 更改密码、邮箱、个人资料、收货地址等。
    *   **执行金融操作**: 非法转账、购买商品、消耗账户余额。
    *   **发布/删除内容**: 以用户身份发帖、评论、点赞、投票、删除数据。
    *   **管理操作**: 如果受害者是管理员，攻击者可能添加/删除用户、修改用户权限、更改系统设置。
    *   **其他**: 强制关注、强制添加好友、发起恶意投票等。
*   **利用信任**: CSRF 攻击利用了网站对其已认证用户的信任，破坏了用户在线活动的安全感。
*   **潜在的利用与隐蔽性**: CSRF 攻击悄无声息地工作，利用的是标准的浏览器行为，通常不需要高级恶意软件。用户可能完全没有意识到攻击的发生，使他们容易受到重复利用。

**示例 (银行转账):**

假设用户给 `spisec` 转账 1000 元的正常请求 URL 如下（简化示例）：
`http://bank.com/transfer?to=spisec&amount=1000`

攻击者可以构造一个指向自己账户的恶意 URL：
`http://bank.com/transfer?to=hacker&amount=10000`

如果攻击者诱导已登录 `bank.com` 的用户访问这个 URL（例如通过在其他网站嵌入一个 `<img src="http://bank.com/transfer?to=hacker&amount=10000">`），用户的浏览器就会自动带上 `bank.com` 的 Cookie 发送这个请求。如果 `bank.com` 没有 CSRF 防护，这笔非预期的转账就会成功。

CSRF 经常与 XSS (跨站脚本攻击) 结合使用，以实现更复杂、更隐蔽的攻击（例如，XSS 可以用来窃取 CSRF Token 或发起更复杂的 AJAX CSRF 请求）。

### 四、 CSRF 分类与常见利用方式 (Classification and Common Exploitation)

CSRF 漏洞通常根据触发请求的 HTTP 方法和技术进行分类：

*   **GET 型 CSRF**:
    *   **利用方式**: 通过 HTML 标签的 `src` 或 `href` 属性，这些标签在加载时会发起 GET 请求。常见如：
        *   `<img>` 标签的 `src` 属性。
        *   `<script>` 标签的 `src` 属性。
        *   `<iframe>` 标签的 `src` 属性。
        *   `<a>` 标签的 `href` 属性 (需要用户点击)。
        *   CSS 中的 `background: url(...)`。
        *   `<link rel="stylesheet" href="...">`。
    *   **特点**: 构造简单，易于通过链接、图片等方式传播。通常用于读取数据或执行设计不当的、可通过 GET 请求改变状态的操作。
    *   **示例 (隐藏图片利用)**: 攻击者可以在恶意页面中插入一个 0x0 像素（用户不可见）的图片，其 `src` 指向目标网站的一个会产生副作用的 GET 请求 URL。例如：
        ```html
        <!-- 假设访问此 URL 会将受害者账户的 1000 元转给 GB82MYBANK5698 -->
        <img src="http://mybank.thm:8080/dashboard.php?to_account=GB82MYBANK5698&amount=1000" width="0" height="0" border="0">
        ```
        或者将恶意 URL 放在一个诱导用户点击的链接中：
        ```html
        <a href="http://mybank.thm:8080/dashboard.php?to_account=GB82MYBANK5698&amount=1000" target="_blank">点击这里领取奖励！</a>
        ```
        当已登录 `mybank.thm` 的用户访问包含此代码的页面或点击链接时，请求会被发送，如果后端没有验证，转账就会发生。

*   **POST 型 CSRF (传统 CSRF)**:
    *   **利用方式**: 需要构造一个 HTML `<form>`，其 `action` 指向目标网站的操作 URL，`method` 为 `POST`，并包含所有必要的参数。然后通过 JavaScript 自动提交这个表单。
    *   **特点**: 主要针对需要通过 POST 请求执行的敏感操作（如修改密码、创建用户、提交订单等）。攻击者通常会将这个自动提交的表单放在一个恶意页面上，诱导用户访问。
    *   **示例**:
        ```html
        <html>
          <body onload="document.csrfForm.submit()"> <!-- 页面加载时自动提交 -->
            <form name="csrfForm" action="http://target.com/change_password" method="POST">
              <input type="hidden" name="new_password" value="hackedPassword123">
              <input type="hidden" name="confirm_password" value="hackedPassword123">
              <!-- 可能还需要其他必要的参数 -->
            </form>
            <p>页面加载中...</p>
          </body>
        </html>
        ```

*   **XMLHttpRequest CSRF (异步 CSRF)**:
    *   **利用方式**: 使用 JavaScript 中的 `XMLHttpRequest` 对象或 `Fetch API` 发起异步的 HTTP 请求（GET, POST, PUT, DELETE 等）到目标网站的 API 端点。
    *   **特点**: 常见于现代 Web 应用（单页应用 SPA 等），这些应用大量使用 AJAX 进行前后端交互，用户操作通常不引起整个页面刷新。攻击者可以构造恶意脚本，在用户访问恶意页面时，在后台悄悄地向目标网站的 API 发送伪造的请求。
    *   **示例 (更新邮箱)**: 假设 `mailbox.thm/api/updateEmail` 是一个接受 POST 请求更改用户邮箱设置的 API。攻击者可以在恶意页面嵌入如下脚本：
        ```javascript
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://mailbox.thm/api/updateEmail', true);
        // 如果目标 API 需要特定的 Content-Type
        xhr.setRequestHeader('Content-Type', 'application/json;charset=UTF-8');
        // 注意：浏览器会自动发送 mailbox.thm 的 cookie
        xhr.send(JSON.stringify({ email: 'attacker@evil.com' }));
        ```
        如果 `mailbox.thm` 的 API 没有 CSRF 防护，并且仅依赖 Cookie 认证，那么当已登录的用户访问包含此脚本的页面时，他们的邮箱设置会被更改。

*   **基于 Flash 的 CSRF (已过时)**:
    *   利用 Adobe Flash Player 组件中的漏洞发起 CSRF 攻击。由于 Flash 已于 2020 年底停止支持，这种方式现在已不常见，但对于仍在使用 Flash 的遗留系统可能存在风险。

**滥用 `$_REQUEST`**: 在 PHP 中，`$_REQUEST` 变量默认会同时包含 `$_GET`, `$_POST`, 和 `$_COOKIE` 的数据。如果一个本应只接受 POST 请求的敏感操作（如修改密码）因为使用了 `$_REQUEST` 来获取参数，而没有检查 `$_SERVER['REQUEST_METHOD']` 是否为 POST，那么它就可能被简单的 GET 型 CSRF 攻击（例如通过 `<img>` 标签）利用。

### 五、 CSRF 漏洞检测 (Detection)

检测 CSRF 漏洞通常涉及手动分析和测试，验证应用程序是否正确实施了防御机制：

1.  **捕获正常请求**: 使用代理工具（如 Burp Suite）登录目标应用程序，并执行一个你想要测试的敏感操作（如修改个人资料、添加购物车、删除帖子）。捕获执行该操作的 HTTP 请求。
2.  **识别潜在防御机制**: 检查捕获的请求：
    *   **CSRF Token**: 是否存在一个看起来随机的、唯一的参数，可能在表单隐藏字段、URL 参数或 HTTP 请求头（如 `X-CSRF-Token`）中？
    *   **`Origin` 请求头**: 对于跨域请求（尤其是 POST/PUT/DELETE），浏览器通常会发送 `Origin` 头。服务器是否检查它？
    *   **`Referer` 请求头**: 请求中是否有 `Referer` 头？服务器是否检查它？
3.  **移除/修改 Token**: 如果存在 CSRF Token，尝试以下操作并重放请求：
    *   完全移除 Token 参数。
    *   将 Token 值置空。
    *   将 Token 值修改为一个无效的、或属于其他用户会话的 Token。
    *   观察服务器响应。如果请求仍然成功执行（返回 2xx 或 3xx 状态码，且操作实际生效），则存在 CSRF 漏洞。
4.  **修改/移除 `Origin` / `Referer` 头**:
    *   尝试移除 `Origin` 头（如果存在）并重放。
    *   尝试移除 `Referer` 头并重放。
    *   尝试将 `Referer` 头修改为另一个域名的 URL（例如 `http://evil.com`）并重放。
    *   观察响应。如果服务器在这些头缺失或不匹配预期时仍然处理请求，表明它没有（或没有正确地）使用这些头进行 CSRF 防御。
5.  **检查请求方法**: 如果一个敏感操作可以通过 GET 请求执行，这本身就是一个 CSRF 风险（更容易被利用）。尝试将 POST 请求改为 GET 请求（带上所有参数）看是否能成功。
6.  **生成 PoC (Proof of Concept)**: 如果确认存在漏洞，可以生成一个简单的 HTML PoC（例如一个自动提交的表单或一个包含恶意 `<img>` 标签的页面）。在一个已登录目标网站的浏览器中打开该 PoC 文件/页面，验证攻击是否能够成功执行。

**容易出现 CSRF 漏洞的地方:**

*   用户资料修改（密码、邮箱、地址等）
*   账户管理（添加/删除用户、修改权限）
*   金融交易、支付接口、购物车操作
*   内容管理（发帖、评论、删除内容）
*   社交互动（投票、点赞、关注、添加好友）
*   系统管理功能（数据库备份/恢复、修改配置）

### 六、 CSRF 攻击案例与进阶利用 (Attack Examples and Advanced Techniques)

*   **本地网络设备 CSRF**: 许多内部网络设备（路由器、交换机）的 Web 管理界面存在 CSRF 漏洞，且常使用默认密码。攻击者可以抓取开启远程管理、修改 Wi-Fi 密码等操作的请求（通常是 GET），构造恶意 URL（如 `<img src="http://192.168.1.1/apply.cgi?enable_remote_admin=1&...">`），诱导内网管理员访问包含此 URL 的外部网页。管理员的浏览器会自动带上管理界面的 Cookie 发送请求，从而在管理员不知情的情况下更改设备设置。

*   **利用自解压文件**: 攻击者可以将 CSRF 攻击代码（例如一个指向目标网站恶意操作的 URL）嵌入到压缩文件（如 RAR）的自解压选项中（例如，在解压后自动打开一个 URL）。诱导用户下载并执行。

*   **结合 Burp Suite 添加管理员账号**: 如果目标网站添加管理员的功能存在 CSRF 漏洞，攻击者可以抓取正常添加管理员的 POST 请求，修改其中的参数（如新管理员用户名、密码），然后使用 Burp Suite 的 CSRF PoC 生成功能创建一个自动提交的表单。诱导已登录的管理员访问包含此 PoC 的页面，即可创建恶意管理员账号。

*   **双重提交 Cookie (Double Submit Cookie) 绕过**:
    *   **机制**: 服务器生成一个 CSRF Token，同时将其设置在用户的 Cookie 中，并将其包含在页面的表单隐藏字段里。提交时，服务器比较 Cookie 中的 Token 和表单中的 Token 是否一致。
    *   **绕过场景**:
        *   **可预测的 Token**: 如果 Token 生成算法不安全、可预测（例如基于用户 ID 的 Base64 编码，如 `mybank.thm` 案例所示），攻击者就可以计算出受害者的 Token。
        *   **子域名 Cookie 注入**: 如果攻击者能控制目标域的一个子域名（例如 `attacker.mybank.thm`），并且服务器的 Cookie 没有正确设置 `Domain` 属性（或设置得过于宽泛），攻击者可能可以在子域名上为父域名（`mybank.thm`）设置一个伪造的 CSRF Token Cookie。
        *   **XSS 漏洞**: 如果存在 XSS 漏洞，攻击者可以通过脚本读取页面中的 CSRF Token，然后构造并发送带有正确 Token 的伪造请求。
        *   **会话固定/劫持**: 如果能劫持用户会话，自然也就能获取 CSRF Token。
    *   **`mybank.thm` 密码更改案例**: 攻击者发现 `mybank.thm` 使用双重提交 Cookie，但 CSRF Token 只是用户账号的 Base64 编码 (`base64_encode("GB82MYBANK5699")`)。攻击者控制了子域名 `attacker.mybank.thm`。攻击流程：
        1.  诱导受害者 Josh 点击一个链接，该链接指向 `attacker.mybank.thm`。
        2.  `attacker.mybank.thm` 页面包含一个 PHP 脚本，该脚本使用 `setcookie()` 函数为父域 `mybank.thm` 设置了一个伪造的 `csrf-token` Cookie，其值为 Josh 账号的 Base64 编码。
        3.  该页面同时包含一个自动提交的表单，`action` 指向 `mybank.thm:8080/changepassword.php`，`method` 为 POST，包含修改后的密码，以及一个隐藏的 `csrf_token` 字段，其值也设置为 Josh 账号的 Base64 编码。
        4.  当表单提交到 `mybank.thm` 时，服务器检查到 Cookie 中的 `csrf-token` 和表单中的 `csrf_token` 经过 Base64 解码后都等于 Josh 的账号，验证通过，密码被修改。

*   **SameSite Cookie 绕过**:
    *   **SameSite 属性**: 控制浏览器在跨站请求时是否发送 Cookie。
        *   `Strict`: 完全禁止跨站发送 Cookie。最安全，但可能影响用户体验。
        *   `Lax`: (多数现代浏览器默认值) 允许在顶层导航（点击链接跳转）和安全的 HTTP 方法（GET, HEAD, OPTIONS）的跨站请求中发送 Cookie。阻止了大多数 POST 型 CSRF 和通过 `<img>`, `<iframe>` 等发起的 GET 型 CSRF。
        *   `None`: 允许在所有跨站请求中发送 Cookie，但必须同时设置 `Secure` 属性（即 Cookie 只能通过 HTTPS 发送）。
    *   **利用 `Lax`**: 如果敏感操作可以通过 GET 请求触发（如 `mybank.thm` 的注销功能 `logout.php`），并且对应的 Session Cookie 是 `Lax`，攻击者仍然可以通过构造一个简单的链接 `<a href="http://mybank.thm:8080/logout.php">...</a>` 来诱导用户点击，从而触发 CSRF 注销。
    *   **利用 Chrome `Lax`+POST 2分钟窗口**: 早期 Chrome 对没有显式设置 `SameSite` 属性的 Cookie 有一个特殊处理：在 Cookie 被设置或更新后的 2 分钟内，即使是 `Lax` (隐式默认)，也会在跨站 POST 请求中发送。攻击者可以利用这一点，先诱导用户触发一个更新目标 Cookie 的操作（如 `mybank.thm` 的登出操作会更新 `isBanned` Cookie），然后在 2 分钟内立即发起一个跨站 POST 请求到另一个需要该 Cookie 的端点（如 `index.php` 用于设置 `isBanned` 状态）。
    *   **注意**: 浏览器的具体行为可能随版本更新而变化，依赖这种特定窗口期的利用方式可能不再可靠或适用范围变窄。但它揭示了理解 Cookie 策略细节的重要性。

*   **其他相关技术**:
    *   **XMLHttpRequest 漏洞利用**: 使用 AJAX 发起 CSRF，需要注意目标 API 是否有 CORS 策略限制以及 CSRF 防护。
    *   **CORS 配置错误**: 如果服务器 `Access-Control-Allow-Origin` 设置为 `*` 或一个攻击者可控的源，并且 `Access-Control-Allow-Credentials` 设置为 `true`（**注意：规范禁止这两者同时使用，但某些实现可能有误**），或者即使没有 `Allow-Credentials: true` 但 API 认证不依赖 Cookie，也可能辅助 CSRF 或导致其他跨域问题。
    *   **Referer 头部绕过**: 依赖 `Referer` 头进行防御是不可靠的，因为：
        *   用户可以通过浏览器设置、隐私插件或代理禁用 `Referer`。
        *   从 HTTPS 页面跳转到 HTTP 页面时，浏览器通常不发送 `Referer`。
        *   HTML `meta` 标签 (`<meta name="referrer" content="no-referrer">`) 或 `Referrer-Policy` HTTP 头可以控制 `Referer` 的发送策略。

### 七、 CSRF 防御措施 (Defense / Mitigation)

防御 CSRF 的核心思想是确保请求确实是由用户本人在其当前浏览的网站上主动、有意发起的。以下是常用且推荐的防御策略（应采用纵深防御，结合多种方法）：

1.  **Synchronizer Token Pattern (Anti-CSRF Tokens)**:
    *   **原理**: 这是目前最广泛、最可靠的 CSRF 防御方法。服务器为用户的每个会话（或每个请求）生成一个唯一的、不可预测的、与会话绑定的随机令牌 (Token)。
        *   **嵌入**: 对于需要保护的表单，将此 Token 作为隐藏字段 (`<input type="hidden" name="csrf_token" value="...">`) 嵌入。
        *   **发送**: 对于 AJAX 请求，可以将 Token 放在自定义 HTTP 请求头（如 `X-CSRF-Token`）中，或包含在请求体中。
        *   **验证**: 服务器在收到请求后，必须从用户会话中取出对应的 Token，并与请求中提交的 Token 进行比较。只有两者匹配，请求才被视为合法。
    *   **关键点**:
        *   Token 必须是不可预测的（使用安全的随机数生成器）。
        *   Token 必须与用户会话绑定。
        *   Token 应有时效性（虽然不总是强制）。
        *   Token 不应通过 URL 参数传递（可能在 `Referer` 中泄露）。
    *   **双重提交 Cookie 模式 (作为 Token 实现方式之一)**: 将 Token 同时存在 Cookie 和请求参数中，服务器比较两者是否一致。优点是不需要在服务器端存储 Token，缺点是如果子域名可被攻击者控制且 Cookie 设置不当，可能被绕过（如前述案例）。

2.  **检查标准 HTTP 请求头 (辅助手段)**:
    *   **`Origin` 头**: 浏览器在发送跨域请求（尤其是 POST, PUT, DELETE, 或带凭证的 CORS 请求）时会自动添加 `Origin` 头，指示请求发起的来源域。服务器可以检查 `Origin` 头是否在可信来源的白名单内。
    *   **`Referer` 头**: `Referer` 头指示请求是从哪个页面跳转过来的。服务器可以检查 `Referer` 是否来自可信的域。
    *   **限制**:
        *   不能完全依赖这两个头。`Referer` 可能缺失或被用户禁用。`Origin` 头并非所有请求类型都会发送（例如同源请求、某些 GET 请求）。
        *   检查逻辑要严格，避免配置错误（如信任了不安全的子域）。
        *   `Origin` 头通常比 `Referer` 头更可靠一些。

3.  **SameSite Cookie 属性 (浏览器层面防御)**:
    *   **原理**: 指示浏览器在跨站请求时如何处理 Cookie。这是非常重要的防御机制。
    *   **设置**: 在设置 Cookie 时添加 `SameSite` 属性：
        *   `SameSite=Strict`: 提供最强保护，几乎完全阻止 CSRF，但可能影响从外部链接跳转回网站时的用户体验（可能需要重新登录）。
        *   `SameSite=Lax`: (推荐默认值) 平衡了安全性和可用性。阻止了跨站的 POST 请求和通过 `<img>`, `<iframe>` 等嵌入资源发起的 GET 请求携带 Cookie，但允许顶层导航 GET 请求携带。能防御大多数 CSRF 场景。
        *   `SameSite=None`: 允许跨站发送 Cookie，但**必须**同时设置 `Secure` 属性（`SameSite=None; Secure`），确保 Cookie 只通过 HTTPS 传输。适用于需要跨域验证身份的场景（如 SSO、嵌入式内容）。
    *   **最佳实践**: 对会话 Cookie 和其他敏感 Cookie 优先考虑设置为 `Lax` 或 `Strict`。

4.  **增加用户交互验证 (关键操作)**:
    *   **验证码 (CAPTCHA)**: 在执行非常敏感的操作（如转账、修改关键设置）前，要求用户输入验证码。
    *   **重新认证**: 要求用户再次输入密码。
    *   **二次验证 (2FA/MFA)**: 要求用户提供短信验证码、OTP（一次性密码）或其他第二因素凭证。
    *   **适用场景**: 用于风险最高的操作，以牺牲部分用户体验换取更高的安全性。

5.  **遵循 HTTP 方法语义**:
    *   **GET 请求**: 严格用于获取资源，不应有任何状态改变的副作用（幂等性）。
    *   **POST/PUT/DELETE 请求**: 用于执行状态改变的操作。
    *   避免仅通过 GET 请求执行敏感操作，因为 GET 请求更容易被 CSRF 利用（如通过 `<img>` 标签）。

### 八、 给不同角色的建议 (Recommendations)

*   **渗透测试员 / 红队人员**:
    *   **全面测试**: 积极测试应用程序是否存在 CSRF 漏洞，尝试绕过现有防御机制。
    *   **边界验证**: 评估输入验证、Token 验证的严格性。
    *   **请求头分析**: 检查 `Origin`, `Referer`, `SameSite`, `CORS` 相关头部的配置和有效性。
    *   **会话管理**: 检查会话令牌的安全性（生成、传输、验证）。
    *   **场景模拟**: 探索各种 CSRF 利用场景，包括结合 XSS、利用逻辑漏洞等。
    *   **关注细节**: 检查 Token 是否可预测，Cookie 属性设置是否恰当，是否存在 GET 型敏感操作等。

*   **安全开发人员 / 编码者**:
    *   **实施 Anti-CSRF Token**: 必须为所有状态改变的请求（非 GET 请求）实施强大的 Anti-CSRF Token 机制（推荐 Synchronizer Token Pattern）。确保 Token 不可预测、与会话绑定。
    *   **设置 SameSite Cookie**: 为所有 Cookie（尤其是会话 Cookie）设置合适的 `SameSite` 属性（优先 `Lax` 或 `Strict`）。
    *   **检查 Origin/Referer (可选补充)**: 可以作为附加防御层，但不要作为主要防御手段。
    *   **使用框架内置防御**: 主流 Web 框架通常内置了 CSRF 防护功能，务必正确启用和配置。
    *   **遵循 HTTP 方法**: 严格区分 GET 和 POST/PUT/DELETE 的用途。
    *   **用户交互验证**: 对高风险操作增加验证码、重新认证或 MFA。
    *   **内容安全策略 (CSP)**: 虽然主要防御 XSS，但可以限制恶意脚本的来源，间接增加 CSRF 攻击的难度。
    *   **Referrer Policy**: 设置 `Referrer-Policy` HTTP 头（例如 `strict-origin-when-cross-origin` 或 `no-referrer`）可以控制 `Referer` 头的发送，增强隐私性，但也会影响依赖 `Referer` 的（不可靠的）CSRF 防御。
    *   **避免敏感信息在 URL 中**: 不要在 URL 参数中传递敏感信息或 Session ID。