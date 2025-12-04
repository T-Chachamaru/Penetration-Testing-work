#### 概述：什么是 GraphQL？ (Overview: What is GraphQL?)

**GraphQL** 是一种现代的 API 查询语言，它允许客户端精确地指定它们需要从服务器获取哪些数据——不多也不少。与返回固定数据结构的传统 REST API 不同，GraphQL 提供了更高的效率和灵活性，但同时也引入了新的攻击面。

##### 关键组件 (Key Components)

- **模式 (Schema)**: API 的蓝图，定义了所有可用的数据类型、字段及其关系，是客户端与服务器之间的“合同”。
    
- **查询 (Query)**: 用于从服务器**获取**数据。
    
- **变异 (Mutation)**: 用于**修改**服务器上的数据（创建、更新、删除）。
    

##### GraphQL vs. REST API

|特性|**GraphQL**|**REST API**|
|---|---|---|
|**端点**|通常是**单一端点** (如 `/graphql`)|**多个端点** (如 `/users`, `/posts`)|
|**数据获取**|客户端精确选择所需字段|服务器返回固定的数据结构|
|**过度/不足获取**|通过精确查询避免|常见|
|**模式**|强类型且自文档化|依赖外部文档|
|**批量请求**|单次请求即可获取多个相关资源|通常需要多次 API 调用|

##### 查询 (Queries) 与 变异 (Mutations)

- **查询 (Query)**: 用于读取数据，类似于 REST 中的 `GET` 请求。
    
    GraphQL
    
    ```
    # 请求：获取 ID 为 "123" 的用户的姓名和邮箱
    {
      user(id: "123") {
        name
        email
      }
    }
    ```
    
    JSON
    
    ```
    # 响应
    {
      "data": {
        "user": { "name": "John Doe", "email": "john@example.com" }
      }
    }
    ```
    
- **变异 (Mutation)**: 用于修改数据，类似于 REST 中的 `POST`, `PUT`, `DELETE` 请求。
    
    GraphQL
    
    ```
    # 请求：更新 ID 为 "123" 的用户的姓名
    mutation {
      updateUser(id: "123", name: "Jane Doe") {
        id
        name
      }
    }
    ```
    
    JSON
    
    ```
    # 响应
    {
      "data": {
        "updateUser": { "id": "123", "name": "Jane Doe" }
      }
    }
    ```
    

##### 嵌套查询与片段 (Nested Queries and Fragments)

- **嵌套查询**: 允许在一次请求中获取多个关联的资源，极大地减少了请求次数。
    
    GraphQL
    
    ```
    {
      user(id: "123") {
        name
        posts {
          title
          comments {
            text
          }
        }
      }
    }
    ```
    
- **片段 (Fragments)**: 允许重用查询的一部分，使代码更简洁。
    
    GraphQL
    
    ```
    fragment UserDetails on User {
      name
      email
    }
    
    {
      user(id: "123") {
        ...UserDetails
      }
    }
    ```
    

#### 1. 发现 GraphQL 端点 (Discovering GraphQL Endpoints)

识别 GraphQL 端点是进行安全评估的第一步。

1. **检查网络流量**: 使用浏览器开发者工具 (F12) 的“网络”标签页，查找包含 `query` 或 `mutation` 字段的 POST 请求。
    
2. **搜索 JavaScript 文件**: 在前端代码中搜索关键词，如 `graphql`, `/graphql` 或 `mutation`。
    
3. **测试常见端点名称**: 手动或使用 Fuzzing 工具（如 `wfuzz`）测试常见的端点路径，如：
    
    - `/graphql`
        
    - `/api/graphql`
        
    - `/gql`
        
4. **触发错误信息**: 向可疑端点发送一个空的 POST 请求，服务器的错误响应可能会暴露其 GraphQL 的身份。
    

#### 2. 常见 GraphQL 漏洞 (Common GraphQL Vulnerabilities)

- **过度数据暴露 (Excessive Data Exposure)**: 如果后端访问控制不当，攻击者可以请求模式中定义的任何字段，即使是敏感字段。
    
    GraphQL
    
    ```
    # 恶意查询
    {
      user(id: "1") {
        id
        username
        email
        password  # 敏感字段
        is_admin  # 敏感字段
      }
    }
    ```
    
- **注入攻击 (Injection Attacks)**: 当用户输入未经正确清理就直接拼接到后端查询（如 SQL）中时，就会发生注入攻击。
    
- **通过复杂查询实施拒绝服务 (DoS)**: 攻击者可以通过构造消耗大量服务器资源的查询来发起 DoS 攻击。
    
    - **深度嵌套查询**:
        
        GraphQL
        
        ```
        {
          user(id: "123") {
            friends { friends { friends { name } } } # 极深的嵌套
          }
        }
        ```
        
    - **批量查询**: 在单个请求中包含数百个查询。
        
        GraphQL
        
        ```
        {
          user1: user(id: "1") { name }
          user2: user(id: "2") { name }
          # ... 重复数百次
        }
        ```
        

#### 3. 内省查询 (Introspection Queries)

##### 什么是 GraphQL 内省？

内省 (Introspection) 是 GraphQL 的一项内置功能，它允许客户端**查询 API 的模式 (Schema) 本身**。开发者可以通过内省来探索 API 的所有类型、字段、查询和变异，而无需查阅外部文档。

GraphQL

```
# 一个标准的内省查询
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

##### 生产环境中暴露内省的安全风险

在生产环境中启用内省会带来巨大的安全风险：

1. **模式枚举**: 攻击者可以获取 API 的完整地图，为精确、有针对性的攻击提供便利。
    
2. **敏感数据暴露**: 即使敏感字段本身受访问控制保护，它们在模式中的存在也可能暴露信息。
    
3. **为利用进行侦察**: 攻击者可以利用完整的模式信息来构造复杂的查询，以利用其他漏洞（如 DoS 或数据暴露）。
    
4. **暴露隐藏功能**: 已弃用或仅供内部使用的操作可能会被暴露。
    

#### 4. 漏洞详解：GraphQL SQL 注入

当 GraphQL 解析器（Resolver）将用户输入直接拼接到 SQL 语句中时，就会发生 SQL 注入。

- **易受攻击的解析器代码**:
    
    JavaScript
    
    ```
    const resolvers = {
      Query: {
        user: (_, { id }) => database.query(`SELECT * FROM users WHERE id = ${id}`)
      }
    };
    ```
    
- **恶意查询**: 攻击者可以在 `id` 参数中注入 SQL 代码。
    
    GraphQL
    
    ```
    # 注入的 payload: "1; DROP TABLE users; --"
    {
      user(id: "1; DROP TABLE users; --") {
        name
      }
    }
    ```
    
- **最终执行的 SQL**:
    
    SQL
    
    ```
    SELECT * FROM users WHERE id = 1; DROP TABLE users; --;
    ```
    

#### 5. 安全强化 GraphQL (Hardening GraphQL)

1. 在生产环境中禁用内省
    
    大多数 GraphQL 库都允许轻松禁用内省。
    
    JavaScript
    
    ```
    // 在 Apollo Server 中禁用内省
    const server = new ApolloServer({
      schema,
      introspection: false
    });
    ```
    
2. 限制查询深度和复杂度
    
    为防止 DoS 攻击，应限制查询的最大深度和复杂度。
    
    JavaScript
    
    ```
    // 限制查询深度（例如，最多 5 层）
    const { depthLimit } = require('graphql-depth-limit');
    const server = new ApolloServer({
      schema,
      validationRules: [depthLimit(5)]
    });
    
    // 限制查询复杂度（为每个字段分配分数，并设置总分上限）
    const { createComplexityLimitRule } = require('graphql-validation-complexity');
    const complexityRule = createComplexityLimitRule(1000);
    const server = new ApolloServer({
        schema,
        validationRules: [complexityRule]
    });
    ```
    
3. 使用参数化查询
    
    这是防止注入的根本方法。始终使用参数化查询或预处理语句，绝不将用户输入直接拼接到查询字符串中。
    
    JavaScript
    
    ```
    // 安全的解析器代码
    const resolvers = {
      Query: {
        users: async (_, { username }) => {
          const connection = await mysql.createConnection(dbConfig);
          const query = `SELECT * FROM users WHERE username = ?`;
          // 使用 .execute() 并将用户输入作为参数传递
          const [rows] = await connection.execute(query, [username]);
          await connection.end();
          return rows;
        },
      },
    };
    ```