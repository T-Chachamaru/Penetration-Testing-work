### MongoDB 基础概念

MongoDB 是一个流行的 NoSQL（非关系型）数据库，它以文档（Document）的形式存储数据，而不是像传统关系型数据库（MySQL, PostgreSQL 等）那样使用表（Table）和行（Row）。

1.  **文档 (Document):** MongoDB 的基本数据单元，类似于关系数据库中的一条记录或一行数据。文档是一个 BSON (Binary JSON) 对象，由键值对（Field-Value Pairs）组成，结构灵活，可以包含嵌套的文档和数组。
    *   **示例员工文档:**
        ```json
        {
          "_id" : ObjectId("5f077332de2cdf808d26cd74"), // 自动生成的唯一标识符
          "username" : "lphillips",
          "first_name" : "Logan",
          "last_name" : "Phillips",
          "age" : 65, // 注意：原始笔记中是字符串"65"，这里改为数字更常见
          "email" : "lphillips@example.com"
        }
        ```

2.  **集合 (Collection):** 一组 MongoDB 文档的容器，类似于关系数据库中的表。集合不强制要求其内部的文档具有相同的结构（Schema-less），但通常实践中一个集合内的文档会有相似的结构。

3.  **数据库 (Database):** 集合的容器。一个 MongoDB 服务器可以承载多个数据库，每个数据库可以包含多个集合。这是最高层次的组织结构。

**层次结构:** `文档 (Document) -> 集合 (Collection) -> 数据库 (Database)`

### MongoDB 查询基础

MongoDB 使用自己的查询语言（通常归类为 NoSQL 的一种）来检索数据。查询的核心是构建一个**查询文档 (Query Document)**，它定义了筛选条件。

1.  **查询结构:** 查询通常是一个包含字段和期望值的文档（关联数组/对象），用于匹配目标集合中的文档。这类似于 SQL 中的 `WHERE` 子句。
2.  **简单查询 (精确匹配):**
    *   查找姓氏为 "Sandler" 的所有文档：
        ```json
        { "last_name": "Sandler" }
        ```
3.  **多条件查询 (逻辑 AND):**
    *   查找性别为 "male" 且姓氏为 "Phillips" 的文档：
        ```json
        { "gender": "male", "last_name": "Phillips" }
        ```
4.  **使用查询操作符 (Query Operators):** MongoDB 提供了一系列以 `$` 开头的操作符，用于实现更复杂的查询逻辑（如比较、逻辑运算、元素匹配、地理空间查询等）。操作符通常作为字段的值嵌套在查询文档中。
    *   查找年龄小于 50 岁的文档：
        ```json
        { "age": { "$lt": 50 } }
        ```
        这里 `$lt` 是 "less than"（小于）操作符。
    *   **常用操作符示例:** `$gt` (大于), `$lte` (小于等于), `$gte` (大于等于), `$ne` (不等于), `$in` (在数组中), `$nin` (不在数组中), `$regex` (正则表达式匹配), `$exists` (字段是否存在) 等。
    *   **官方文档参考:** [MongoDB Query Operators](https://docs.mongodb.com/manual/reference/operator/query/)

### NoSQL 注入概述

NoSQL 注入的根本原因与 SQL 注入类似：**将不受信任的用户输入不正确地嵌入或连接到数据库查询命令中，从而允许攻击者改变原始查询的结构或逻辑。**

与 SQL 主要处理字符串拼接不同，NoSQL（特别是 MongoDB）查询通常是结构化的文档（如 JSON/BSON）。因此，注入攻击往往涉及操纵这种结构，而不是仅仅通过引号来“逃逸”字符串。

### NoSQL 注入分类 (按攻击方式)

1.  **语法注入 (Syntax Injection):**
    *   **概述:** 类似于 SQL 注入，目标是破坏原始查询的语法结构，注入任意的数据库命令或查询片段。
    *   **方法:** 可行性很大程度上取决于**后端应用程序代码如何根据用户输入构建 MongoDB 查询对象**。如果代码在创建最终查询对象之前进行了不安全的字符串操作（例如，动态生成字段名或部分查询结构），则可能存在使用特殊字符（如 `}`, `'`, `"`, `;` 等）进行注入的机会。然而，如果代码直接将用户输入映射到查询文档的值（这是更常见的情况），则此类注入较难实现。
    *   **示例 (假设场景):** 如果后端代码像 `db.collection.find("{'username': '" + userInput + "'}")` 这样构造查询（**极不推荐**），那么输入 `a'; db.dropDatabase(); //` 就可能导致灾难性后果。

2.  **操作符注入 (Operator Injection):**
    *   **概述:** 这是针对 MongoDB 等 NoSQL 数据库更常见和典型的注入方式。攻击者并不破坏查询语法，而是**将 NoSQL 查询操作符（如 `$ne`, `$gt`, `$in`, `$regex`, `$where` 等）作为用户输入的值**提供给应用程序。如果应用程序直接将这个包含操作符的输入用作查询条件的值，就会改变查询的预期逻辑。
    *   **目标:** 通常用于绕过认证、水平/垂直权限提升、数据探测或执行拒绝服务。

### NoSQL 注入检测与利用

1.  **理解输入点与后端处理:**
    *   关键在于识别用户输入（来自 URL 参数、POST 表单、JSON 请求体、HTTP 头等）是如何被服务器端语言（如 Node.js, Python, PHP, Java）获取并最终转化为 MongoDB 查询文档（通常是 BSON 对象）的。
    *   不同的语言和框架处理输入的方式不同，特别是对于嵌套参数或数组的处理。

2.  **探测与利用操作符注入:**
    *   **核心技术:** 利用 HTTP 参数的传递方式，使得后端语言将用户的输入解析为一个包含恶意操作符的**对象或数组**，而不是简单的字符串。
        *   **PHP 示例:** URL 参数 `username[$ne]=admin` 可能会被 PHP 解析为 `$_GET['username'] = ['\$ne' => 'admin']`。
        *   **Node.js (Express with body-parser) / JSON:** 如果接受 JSON 请求体，攻击者可以直接发送包含操作符的 JSON 结构：`{"username": {"$ne": "admin"}}`。
    *   **认证绕过 (`$ne`, `$gt`, `$regex` 等):**
        *   **Payload:** 发送类似 `username[$ne]=xxxx&password[$ne]=yyyy` 的请求。
        *   **后端查询可能变为:** `db.collection.find({ "username": { "$ne": "xxxx" }, "password": { "$ne": "yyyy" } })`
        *   **效果:** 这个查询会匹配数据库中任何用户名**不**是 "xxxx" 且密码**不**是 "yyyy" 的用户。如果集合中存在任何用户，查询就会返回结果（通常是第一个匹配的用户），应用程序可能误认为登录成功，从而让攻击者以该用户的身份登录。
    *   **数据枚举/探测 (`$regex`, `$in`, `$nin`):**
        *   **使用 `$regex` 猜测密码长度/模式:**
            *   Payload: `username=admin&password[$regex]=^.{5}$` (尝试 admin 用户)
            *   查询: `db.collection.find({ "username": "admin", "password": { "$regex": "^.{5}$" } })`
            *   效果: 如果返回成功响应（如登录成功），则说明 admin 的密码长度为 5。可以逐步改变正则表达式来猜测字符集、具体字符等（类似 SQL 盲注）。
        *   **使用 `$nin` 探测/绕过:**
            *   Payload: `user[$nin][]=admin&user[$nin][]=pedro&user[$nin][]=john&password[$ne]=asadsd`
            *   查询: `db.collection.find({ "user": { "$nin": ["admin", "pedro", "john"] }, "password": { "$ne": "asadsd" } })`
            *   效果: 查找用户名不在指定列表 ['admin', 'pedro', 'john'] 中，并且密码不是 'asadsd' 的用户。结合应用程序逻辑，可能用于登录非特定用户或探测存在哪些其他用户。
    *   **高危操作符注入 (`$where`):**
        *   **概述:** `$where` 操作符允许在查询中执行任意 JavaScript 代码片段。如果攻击者能将包含 `$where` 的输入注入，将可能导致服务器端 JavaScript 执行，这是**极其危险**的，可能导致远程代码执行 (RCE)。
        *   **Payload (示例):** `username=admin&password[$where]=this.username=='admin'%26%26sleep(5000)` (URL 编码的 `&&`)
        *   **查询:** `db.collection.find({ "username": "admin", "password": { "$where": "this.username=='admin'&&sleep(5000)" } })`
        *   **效果:** 如果 `username` 是 'admin'，则服务器会执行 `sleep(5000)`，导致响应延迟 5 秒（时间盲注探测）。更恶意的 JavaScript 可以用来窃取数据或尝试执行命令。

3.  **探测语法注入:**
    *   如前所述，这依赖于不安全的查询构建方式。
    *   尝试注入可能破坏 BSON/JSON 结构或被不安全字符串拼接函数解释的字符：`'`, `"`, `;`, `}`, `{`, `\`, `$`, `.` 等。
    *   观察应用程序是否返回错误信息，或者行为是否发生意外变化。

### NoSQL 注入防御

防御 NoSQL 注入的核心思想是确保用户输入始终被当作**数据**处理，而不是**代码**或**查询结构**的一部分。

1.  **使用 ODM/库的安全特性:**
    *   **强烈推荐**使用成熟的 Object-Document Mapper (ODM) 库，如 Mongoose (Node.js), MongoEngine (Python), Doctrine MongoDB ODM (PHP), Spring Data MongoDB (Java)。
    *   这些库通常提供安全的 API 来构建查询，内部处理数据类型转换和参数化（类似 SQL 的 PreparedStatement），能有效防止操作符注入。
    *   **避免使用直接构建查询字符串或对象的底层驱动方法，除非你完全理解并能保证输入的安全性。**

2.  **输入验证与清理 (Sanitization):**
    *   **数据类型验证:** 严格检查用户输入是否符合预期的类型（例如，ID 应该是 ObjectId 格式，年龄应该是数字）。拒绝或转换类型不匹配的输入。
    *   **结构验证 (Schema Validation):** 如果接受复杂的输入对象（如 JSON 请求体），在应用层或数据库层（MongoDB 支持 JSON Schema 验证）强制执行数据结构验证。确保输入只包含预期的字段，没有意外的嵌套结构或操作符。
    *   **关键：阻止操作符注入:**
        *   **禁止或清理 `$` 开头的键:** 最有效的防御操作符注入的方法之一是检查用户输入的对象（如果允许的话），不允许任何键名以 `$` 符号开头。或者，在将用户输入合并到查询之前，递归地移除或转义所有以 `$` 开头的键。
        *   **白名单/黑名单:** 如果查询逻辑允许用户指定某些字段或简单操作，使用白名单严格限制允许的字段名和操作符。
    *   **对输出进行编码:** 虽然与注入防御不直接相关，但从数据库取出并在前端显示的数据应进行适当的 HTML 编码，以防止 XSS 攻击。

3.  **最小权限原则:**
    *   应用程序连接 MongoDB 所使用的数据库用户，应只被授予执行其任务所必需的最低权限。例如，只读用户、对特定集合的读写权限等。
    *   避免使用拥有 `dbAdmin`, `clusterAdmin`, `readWriteAnyDatabase` 等高权限角色的账户。
    *   限制对系统集合（如 `system.js`）的访问。

4.  **避免将用户输入用作查询结构的关键部分:**
    *   设计查询时，尽量让用户输入只填充查询条件中的**值 (value)** 部分，而不是**键 (key/field name)** 或**操作符 (operator)**。
    *   例如，避免 `db.collection.find({ [userInputField]: userInputvalue })` 这样的模式，因为用户可能控制了字段名 `userInputField`。

5.  **禁用服务器端脚本 (高风险功能):**
    *   如果业务逻辑不需要，强烈建议在 MongoDB 配置中禁用服务器端 JavaScript 执行（通过 `$where`, `mapReduce`, `group` 命令）。
    *   在 `mongod.conf` 中设置 `security.javascriptEnabled: false` (MongoDB 3.6 及以后版本默认可能已禁用或限制)。这能彻底消除 `$where` 注入的风险。

### 常用危险或需关注的操作符 (MongoDB)

以下是一些在注入场景下特别需要关注的操作符：

*   **`$ne`, `$gt`, `$lt`, `$gte`, `$lte`, `$in`, `$nin`:** 常用于绕过认证或进行数据比较探测。
*   **`$regex`:** 用于基于正则表达式的匹配，可用于盲注式的数据猜测（长度、字符集、内容）。
*   **`$where`:** **极其危险**，允许执行任意服务器端 JavaScript，可能导致 RCE。
*   **`$exists`:** 判断字段是否存在，可用于探测数据结构。
*   **`$type`:** 判断字段的数据类型，可用于探测数据结构。
*   **`$lookup`:** (聚合管道操作符) 用于执行类似 SQL JOIN 的操作，如果注入到聚合查询中，可能跨集合泄露数据。
*   **`mapReduce`, `group`:** (旧版，或特定场景) 也可能涉及服务器端 JavaScript 执行，存在风险。

**参考:** 始终查阅最新的 [MongoDB 官方文档](https://docs.mongodb.com/manual/reference/operator/query/) 获取最全面、准确的操作符信息。

---