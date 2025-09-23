#### 概述：什么是 Osquery？ (Overview: What is Osquery?)

**Osquery** 是由 Facebook 于 2014 年创建的一款开源代理，其核心思想是将整个操作系统抽象为一个**关系数据库**。这使得安全分析师、应急响应人员和威胁猎人可以使用标准的 **SQL 查询**来提问操作系统，从而获取例如正在运行的进程、已创建的用户账户或与可疑域通信的进程等信息。

Osquery 跨平台兼容 Windows, Linux, macOS 和 FreeBSD，被业界广泛使用。

#### 1. Osquery 交互模式 (`osqueryi`) (Osquery Interactive Mode)

与 Osquery 交互最直接的方式是使用其交互式 Shell。

- **启动**: 在终端中运行 `osqueryi`。
    
- **元命令 (Meta-Commands)**: 在 `osqueryi` Shell 中，所有以 `.` 开头的命令都是元命令，用于控制 Shell 本身，而不是查询操作系统。
    
    - `.help`: 显示所有可用的元命令。
        
    - `.tables`: 列出所有可查询的表。
        
        - 你也可以用它来搜索表名，例如 `.tables process` 会列出所有名称中包含 "process" 的表。
            
    - `.schema <table_name>`: 显示指定表的结构，包括所有列名及其数据类型。这是构建查询前至关重要的一步。
        
    - `.mode <mode_name>`: 更改查询结果的显示模式（如 `line`, `column`, `csv`）。
        

#### 2. 创建 SQL 查询 (Creating SQL Queries)

Osquery 使用的是 SQLite 的一个超集，对于分析工作而言，你将主要使用 `SELECT` 语句来查询端点信息，而不会使用 `UPDATE` 或 `DELETE` 来修改系统状态。

##### 基本查询 (Basic Queries)

所有查询都遵循 `SELECT ... FROM ...;` 的基本结构，并以分号结尾。

- **示例**: 查询 `programs` 表中的所有已安装程序（限制只显示 1 条结果）。
    
    SQL
    
    ```
    SELECT * FROM programs LIMIT 1;
    ```
    
- **示例**: 只选择 `programs` 表中的特定列。
    
    SQL
    
    ```
    SELECT name, version, install_location, install_date FROM programs LIMIT 1;
    ```
    

##### 计数 (Counting Results)

使用 `count()` 函数来统计表中的条目总数。

- **示例**: 统计已安装程序的总数。
    
    SQL
    
    ```
    SELECT count(*) FROM programs;
    ```
    

##### 使用 `WHERE` 子句进行筛选 (Filtering with the WHERE Clause)

`WHERE` 子句用于根据特定条件筛选查询结果。

- **示例**: 从 `users` 表中只选择用户名为 'James' 的记录。
    
    SQL
    
    ```
    SELECT * FROM users WHERE username='James';
    ```
    

> **注意**: 某些表（如 `file` 表）**必须**包含 `WHERE` 子句才能返回值，否则会报错。

- **过滤运算符 (Filtering Operators)**:
    

|运算符|符号|含义|
|---|---|---|
|等于|`=`|Equal|
|不等于|`<>`|Not equal|
|大于|`>`|Greater than|
|小于|`<`|Less than|
|大于或等于|`>=`|Greater than or equal to|
|小于或等于|`<=`|Less than or equal to|
|在范围内|`BETWEEN`|Between a range|
|模式匹配|`LIKE`|Pattern wildcard searches|

- **`LIKE` 通配符**:
    
    - `%`: 匹配零个或多个任意字符。
        
    - `_`: 匹配单个任意字符。
        
- **文件路径通配符**:
    
    - `%`: 匹配当前层级的所有文件和文件夹。
        
    - `%%`: **递归**匹配所有层级的文件和文件夹。
        
    - **示例 (`/Users/%/Library/%%`)**: 递归监控每个用户 Library 文件夹内的所有文件和文件夹变更。
        

##### 使用 `JOIN` 连接表 (Joining Tables with JOIN)

`JOIN` 语句可以根据两个表中共享的列（如用户 ID `uid`）将它们连接起来，从而实现跨表查询。

- **场景**: 我们想查看进程列表，并找出运行每个进程的具体用户名。`processes` 表有 `pid` 和 `uid`，`users` 表有 `uid` 和 `username`。
    
- **步骤**:
    
    1. **查询 `processes` 表**:
        
        SQL
        
        ```
        select uid, pid, name, path from processes;
        ```
        
    2. **查询 `users` 表**:
        
        SQL
        
        ```
        select uid, username, description from users;
        ```
        
    3. **使用 `JOIN` 连接查询**:
        
        SQL
        
        ```
        -- 'p' 和 'u' 是表的别名，用于简化查询
        select p.pid, p.name, p.path, u.username
        from processes p
        JOIN users u on u.uid=p.uid
        LIMIT 10;
        ```