# SQL 基础知识笔记

## 一、了解SQL

### 数据库
- 数据库是一种保存有组织数据的容器
### 表
- 存储某种特定类型数据的结构化清单
- 不同数据不应存储在同一张表内（易造成检索困难）
- 表名具有唯一性：通常由数据库名+表名组合构成
- 部分数据库使用数据库拥有者名称作为唯一名组成部分
### 模式
- 描述表的布局及特性
- 包含以下信息：
  - 数据在表中的存储方式
  - 存储数据类型
  - 数据分解方式
  - 各部分信息的命名规则
### 列
- 表的基本组成单元（字段）
- 每个列存储特定类型的信息
- 数据分解原则：
  - 正确分列对分类/过滤至关重要
- 数据类型：
  - 定义列可存储的数据种类（数值/文本/日期/金额等）

### 行
- 数据按行存储
- 每条记录占据独立行
- 表格结构：
  - 垂直方向为列（字段）
  - 水平方向为行（记录）

### 主键
- 唯一标识表中每行的列（或列组合）
- 应用场景：
  - 顾客表 → 顾客编号
  - 订单表 → 订单ID
- 强制建议：始终定义主键

#### 主键条件
1. **唯一性**：任意两行不得有相同主键值
2. **非空性**：每行必须存在主键值（禁止NULL）
3. **稳定性**：主键值不可修改/更新
4. **不可重用性**：删除行的主键不得赋予新行

## 二、检索数据

### 关键字与基础语法
- SQL关键字由英语单词构成（不可用作表/列名）
- 基础检索结构：
  ```sql
  SELECT prod_name FROM Products;  -- 从Products表检索prod_name列
  ```

### 多形式书写规范
SQL语句空格不敏感，等效写法示例：
```sql
-- 多行写法
SELECT prod_name
FROM Products;

-- 单行写法
SELECT prod_name FROM Products;

-- 分段写法
SELECT
prod_name
FROM
Products;
```

### 多列与全列检索
```sql
-- 检索多个指定列
SELECT prod_id, prod_name, prod_price FROM Products;

-- 检索全部列（使用通配符*）
SELECT * FROM Products;
```

### 唯一值检索
```sql
SELECT DISTINCT vend_id FROM Products;  
-- DISTINCT特性：
-- 1. 作用于所有指定列
-- 2. 必须置于列名前
```

### 结果行数限制
不同数据库实现方式：
```sql
-- SQL Server
SELECT TOP 5 prod_name FROM Products;

-- DB2
SELECT prod_name FROM Products
FETCH FIRST 5 ROWS ONLY;

-- Oracle
SELECT prod_name FROM Products
WHERE ROWNUM <=5;

-- MySQL/MariaDB/PostgreSQL/SQLite
SELECT prod_name FROM Products
LIMIT 5;
```

### 分页检索
```sql
-- 标准语法
SELECT prod_name FROM Products
LIMIT 5 OFFSET 5;  -- 从第5行开始取5行

-- 简写语法（注意顺序）
SELECT prod_name FROM Products
LIMIT 3,4;  -- 等效于 LIMIT 4 OFFSET 3
```

### 注释规范
```sql
-- 单行注释
/* 多行注释
   可跨越多行 */
```

### 记
掌握三组关键组合：
1. `SELECT + FROM` 基础检索
2. `SELECT DISTINCT + FROM` 唯一值检索
3. `SELECT + FROM + LIMIT` 分页控制

## 三、排序检索数据

### 基础排序原理
- 默认检索顺序不可靠：可能受数据存储物理顺序或DBMS空间回收机制影响
- 重要原则：未明确排序时，结果顺序无业务意义

### 单列排序
```sql
SELECT prod_name
FROM Products
ORDER BY prod_name;  -- 按字母顺序排序
```
**关键规范**：
1. `ORDER BY` 必须作为SELECT语句最后子句
2. 允许使用非显示列排序（不限于SELECT列表中的列）

### 多列排序
```sql
SELECT prod_id, prod_price, prod_name
FROM Products
ORDER BY prod_price, prod_name; 
```
**执行规则**：
- 先按第一列（prod_price）排序
- 仅在价格相同的情况下，按第二列（prod_name）排序

### 按列位置排序
```sql
SELECT prod_id, prod_name, prod_price
FROM Products
ORDER BY 2, 3;  -- 2对应prod_name，3对应prod_price
```
**优势**：避免重复输入列名  
**注意**：列位置从SELECT列表开始计数

### 降序排序
```sql
-- 单列降序
SELECT prod_id, prod_name, prod_price
FROM Products
ORDER BY prod_price DESC;

-- 混合排序
SELECT prod_id, prod_name, prod_price
FROM Products
ORDER BY prod_price DESC, prod_name;
```
**核心特性**：
- `DESC` 仅作用于前邻列名
- 默认排序为升序（`ASC` 可显式声明但通常省略）

### 记
| 关键字        | 作用范围               | 说明                      |
|---------------|------------------------|---------------------------|
| `ORDER BY`    | 整个结果集             | 基础排序指令              |
| `DESC`        | 前邻单个列             | 降序排列                  |
| `ASC`         | 前邻单个列             | 升序排列（默认可不写）     |
| 列位置数字    | SELECT列表中的列位置   | 简化多列排序书写          |

> **记忆要点**  
> 掌握四类排序控制：
> 1. 基础`ORDER BY`排序
> 2. `DESC`降序控制
> 3. 列位置数字简化写法
> 4. 多列排序的优先级规则

## 四、过滤数据

### 基础过滤语法
```sql
SELECT prod_name, prod_price
FROM Products
WHERE prod_price = 3.49;  -- WHERE子句位于FROM之后，用于指定过滤条件
```

### WHERE操作符大全
| 操作符         | 说明                  | 示例                      |
|-----------------|-----------------------|---------------------------|
| `=`             | 等于                  | WHERE price = 10         |
| `<>` 或 `!=`    | 不等于                | WHERE id <> 'DLL01'      |
| `<`             | 小于                  | WHERE quantity < 100     |
| `<=`            | 小于等于              | WHERE age <= 30          |
| `!<`            | 不小于（非标准）      | WHERE score !< 60        |
| `>`             | 大于                  | WHERE temperature > 38   |
| `>=`            | 大于等于              | WHERE sales >= 1000      |
| `!>`            | 不大于（非标准）      | WHERE level !> 5         |
| `BETWEEN`       | 范围匹配              | WHERE price BETWEEN 5 AND 10 |
| `IS NULL`       | 空值检测              | WHERE name IS NULL       |

**特殊说明**：
- 字符串必须用单引号包裹：`WHERE vend_id <> 'DLL01'`
- 非标准操作符（如!<、!>）可能不被所有DBMS支持

### 范围值检查
```sql
SELECT prod_name, prod_price
FROM Products
WHERE prod_price BETWEEN 5 AND 10;  -- 闭区间包含边界值
```

### 空值检测
```sql
SELECT prod_name
FROM Products
WHERE prod_price IS NULL;  -- 返回价格为空的记录
```

### 重要注意事项
1. **空值特性**：
   - 不会出现在 `=` 或 `<>` 的匹配结果中
   - 必须使用 `IS NULL` 专门检测
2. **条件优先级**：
   - `BETWEEN` 包含边界值
   - 多个条件组合时需注意逻辑顺序

### 记
掌握三大关键过滤方式：
1. `WHERE` 基础条件过滤
2. `BETWEEN` 范围匹配
3. `IS NULL` 空值检测

> **特殊值处理原则**  
> 需特别注意字符串的引号使用和空值的检测方式，这两类值需要特殊语法处理

## 五、高级数据过滤

### 逻辑运算符组合
```sql
-- AND运算符（需同时满足）
SELECT prod_id, prod_name, prod_price
FROM Products
WHERE prod_id = 'DLL01' AND prod_price <= 4;

-- OR运算符（满足其一即可）
SELECT prod_id, prod_name, prod_price
FROM Products
WHERE prod_id = 'DLL01' OR prod_id = 'BRS01';
```

### 运算符优先级
**核心规则**：
- AND 优先级高于 OR
- 建议使用括号明确逻辑关系

**错误示例**：
```sql
WHERE vend_id = 'DLL01' OR vend_id = 'BRS01' AND prod_price > 10
-- 实际执行顺序相当于： 
WHERE vend_id = 'DLL01' OR (vend_id = 'BRS01' AND prod_price > 10)
```

**正确写法**：
```sql
WHERE (vend_id = 'DLL01' OR vend_id = 'BRS01') AND prod_price > 10
```

### IN 运算符
```sql
SELECT prod_name, prod_price
FROM Products
WHERE vend_id IN ('DLL01', 'BRS01'); 
-- 等效于 vend_id = 'DLL01' OR vend_id = 'BRS01'
```
**优势**：
1. 执行效率通常优于多个OR条件
2. 支持动态子查询（可嵌套SELECT语句）
3. 更易维护多条件逻辑

### NOT 运算符
```sql
-- 基础否定
SELECT prod_id
FROM Products
WHERE NOT vend_id = 'DLL01';  -- 等效于 vend_id <> 'DLL01'

-- 组合否定
SELECT *
FROM Orders
WHERE NOT country IN ('CN', 'US');  -- 排除指定国家

WHERE NOT prod_price BETWEEN 5 AND 10  -- 价格不在5-10之间
```
**功能扩展**：
- 可否定 IN/BETWEEN/EXISTS 等子句
- 特别适合反向筛选场景

### 记
| 运算符 | 作用场景                   | 典型用法                     |
|--------|----------------------------|------------------------------|
| AND    | 逻辑与                     | WHERE cond1 AND cond2        |
| OR     | 逻辑或                     | WHERE cond1 OR cond2         |
| IN     | 多值匹配                   | WHERE col IN (val1, val2)    |
| NOT    | 条件取反                   | WHERE NOT cond               |

> **最佳实践建议**  
> 1. 多条件组合时始终使用括号明确优先级  
> 2. IN运算符优先于多个OR连接  
> 3. NOT运算符配合其他条件使用更高效

## 六、用通配符进行过滤

### 通配符基础
- 特殊字符用于匹配字符串片段
- 必须与 `LIKE` 关键字配合使用
- 支持组合字面值和通配符构建搜索条件

### % 通配符
```sql
-- 匹配任意长度字符（包含0个字符）
SELECT prod_id, prod_name
FROM Products
WHERE prod_name LIKE 'Fish%';  -- 匹配Fish开头的所有名称
```

### _ 通配符
```sql
-- 匹配单个任意字符
SELECT prod_id, prod_name
FROM Products
WHERE prod_name LIKE '__ inch teddy bear';  -- 匹配类似"12 inch teddy bear"
```
**注意**：DB2 数据库不支持此通配符

### [] 字符集通配符
```sql
-- 匹配指定字符集中的单个字符
SELECT cust_contact
FROM Customers
WHERE cust_contact LIKE '[JM]%';  -- 匹配J或M开头的名称
```
**适用数据库**：SQL Server/Access

### [^] 否定通配符
```sql
-- 排除指定字符集的匹配
SELECT cust_contact
FROM Customers
WHERE cust_contact LIKE '[^JM]%';  -- 匹配非J/M开头的名称
-- 等效写法：
WHERE NOT cust_contact LIKE '[JM]%'
```
**替代方案**：可用 `NOT LIKE` 实现相同效果

### 通配符对照表
| 通配符 | 功能描述                     | 示例               |
|--------|------------------------------|--------------------|
| `%`    | 任意长度字符匹配             | `'Fish%'`          |
| `_`    | 单个字符匹配                 | `'__ inch'`        |
| `[]`   | 指定字符集匹配               | `'[JM]%'`          |
| `[^]`  | 排除字符集匹配               | `'[^JM]%'`         |

### 记
1. 通配符搜索效率较低，避免过度使用
2. 不同数据库实现存在差异：
   - MySQL使用 `REGEXP` 代替 `[]`
   - Oracle使用 `NOT IN` 实现否定匹配
3. 区分大小写情况需结合数据库配置

## 七、创建计算字段

### 核心概念
- **计算字段**：运行时在SELECT语句中动态创建，不实际存储于数据库表
- **字段 vs 列**：
  - 列：数据库表结构的组成部分
  - 字段：特指通过计算生成的虚拟列

### 字符串拼接实现
不同数据库的拼接方法：
```sql
-- SQL Server
SELECT vend_name + '(' + vend_country + ')'

-- DB2/Oracle/PostgreSQL/SQLite
SELECT vend_name || '(' || vend_country || ')'

-- MySQL/MariaDB
SELECT CONCAT(vend_name, '(', vend_country, ')')
```

### 空格处理函数
```sql
SELECT RTRIM(vend_name) || '(' || RTRIM(vend_country) || ')'
FROM Vendors
-- 常用函数：
-- RTRIM() 去除右侧空格
-- LTRIM() 去除左侧空格 
-- TRIM() 去除两侧空格
```

### 别名应用
```sql
SELECT 
    RTRIM(vend_name) || '(' || RTRIM(vend_country) || ')' AS vend_title
FROM Vendors
```
**别名作用**：
1. 为计算字段命名以便客户端调用
2. 重命名包含非法字符的列
3. 增强列名的可读性

**最佳实践**：始终使用AS关键字声明别名

### 数值运算
```sql
SELECT 
    prod_id,
    quantity,
    item_price,
    quantity * item_price AS expanded_price  -- 支持+-*/运算符
FROM OrderItems
WHERE order_num == 20008  -- 注意：实际应为单等号=，此处保留原始写法
```
**运算规则**：
- 遵循标准数学运算优先级
- 可用括号改变运算顺序

### 记
| 功能                | SQL Server       | 其他数据库         | MySQL系列        |
|---------------------|------------------|--------------------|------------------|
| 字符串拼接          | + 运算符         | \|\| 运算符        | CONCAT()函数     |
| 数值运算            | 标准+-*/         | 标准+-*/           | 标准+-*/         |
| 字段命名            | AS               | AS                 | AS               |

> **关键记忆**  
> 1. 所有计算字段必须通过别名(AS)命名  
> 2. 不同数据库的字符串拼接语法差异较大  
> 3. 数值运算遵循标准数学规则

## 八、使用函数处理数据

### 函数兼容性说明
所有DBMS支持函数，但存在显著差异：
| 功能                | 适用DBMS                          | 函数示例                     |
|---------------------|-----------------------------------|------------------------------|
| 提取子字符串        | DB2/Oracle/PostgreSQL/SQLite     | `SUBSTR()`                   |
|                     | MariaDB/MySQL/SQL Server         | `SUBSTRING()`                |
| 数据类型转换        | DB2/PostgreSQL                   | `CAST()`                     |
|                     | MariaDB/MySQL/SQL Server         | `CONVERT()`                  |
|                     | Oracle                           | 专用转换函数（如`TO_NUMBER`）|
| 获取当前日期        | DB2/PostgreSQL                   | `CURRENT_DATE`               |
|                     | MariaDB/MySQL                    | `CURDATE()`                  |
|                     | Oracle                           | `SYSDATE`                    |
|                     | SQL Server                       | `GETDATE()`                  |
|                     | SQLite                           | `DATE()`                     |

### 文本处理函数
```sql
-- 基础示例
SELECT vend_name, UPPER(vend_name) AS vend_name_upcase
FROM Vendors
ORDER BY vend_name;

-- 常用函数列表
| 函数         | 功能描述                          | 跨DBMS替代方案          |
|--------------|-----------------------------------|-------------------------|
| `LEFT()`     | 返回字符串左侧字符                | `SUBSTRING(col,1,n)`    |
| `LENGTH()`   | 返回字符串长度                    | `LEN()`/`DATALENGTH()`  |
| `LOWER()`    | 转换为小写                        | -                       |
| `LTRIM()`    | 去除左侧空格                      | -                       |
| `RIGHT()`    | 返回字符串右侧字符                | `SUBSTRING(col,-n)`     |
| `RTRIM()`    | 去除右侧空格                      | -                       |
| `SOUNDEX()`  | 生成语音匹配码                    | -                       |

-- SOUNDEX语音匹配示例
SELECT cust_name, cust_contact
FROM Customers
WHERE SOUNDEX(cust_contact) = SOUNDEX('Michael Green');
```

### 日期处理函数
**提取年份示例**：
```sql
-- SQL Server
SELECT order_num
FROM Orders
WHERE DATEPART(yy, order_date) = 2020;

-- PostgreSQL
SELECT order_num
FROM Orders
WHERE DATE_PART('year', order_date) = 2020;

-- Oracle
SELECT order_num
FROM Orders
WHERE EXTRACT(year FROM order_date) = 2020;

-- Oracle日期范围写法
SELECT order_num
FROM Orders
WHERE order_date BETWEEN TO_DATE('2020-01-01', 'yyyy-mm-dd') 
                     AND TO_DATE('2020-12-31', 'yyyy-mm-dd');

-- MySQL/MariaDB/DB2
SELECT order_num
FROM Orders
WHERE YEAR(order_date) = 2020;

-- SQLite
SELECT order_num
FROM Orders
WHERE strftime('%Y', order_date) = '2020';
```

### 数值处理函数
| 函数      | 功能描述                |
|-----------|-------------------------|
| `ABS()`   | 绝对值                  |
| `COS()`   | 余弦值                  |
| `EXP()`   | 指数计算                |
| `PI()`    | 返回π值                 |
| `SIN()`   | 正弦值                  |
| `SQRT()`  | 平方根                  |
| `TAN()`   | 正切值                  |

### 开发建议
> **重要注意事项**  
> 数据库函数的跨平台兼容性较差，过度依赖特定DBMS函数会显著降低SQL代码的可移植性。建议：
> 1. 优先使用ANSI标准函数
> 2. 在必须使用专用函数时添加详细注释
> 3. 将数据库相关函数逻辑封装在数据访问层

## 九、汇总数据

### 聚集函数概览
| 函数       | 功能描述                   | 处理NULL规则         |
|------------|----------------------------|----------------------|
| `AVG()`    | 返回某列的平均值           | 忽略NULL行           |
| `COUNT()`  | 返回某列的行数             | `COUNT(*)`计数所有行 |
| `MAX()`    | 返回某列的最大值           | 忽略NULL值           |
| `MIN()`    | 返回某列的最小值           | 忽略NULL值           |
| `SUM()`    | 返回某列值之和             | 忽略NULL值           |

### 函数详解与示例
#### AVG() 平均值
```sql
-- 基础用法
SELECT AVG(prod_price) AS avg_price FROM Products;

-- 条件过滤
SELECT AVG(prod_price) AS avg_price 
FROM Products
WHERE vend_id = 'DLL01';
```
**注意**：
- 仅用于数值列
- 多列求平均需多次调用

#### COUNT() 计数
```sql
-- 统计所有行
SELECT COUNT(*) AS num_cust FROM Customers;

-- 统计非空值
SELECT COUNT(cust_email) AS num_cust FROM Customers;
```

#### MAX() 最大值
```sql
SELECT MAX(prod_price) AS max_price FROM Products;
```
**特性**：
- 文本数据返回字典序最后的值
- 日期返回最近日期

#### MIN() 最小值
```sql
SELECT MIN(prod_price) AS min_price FROM Products;
```
**特性**：
- 文本数据返回字典序最前的值
- 日期返回最早日期

#### SUM() 求和
```sql
-- 单列求和
SELECT SUM(quantity) AS item_ordered 
FROM OrderItems
WHERE order_num = 20005;

-- 计算表达式
SELECT SUM(item_price*quantity) AS total_price 
FROM OrderItems
WHERE order_num = 20005;
```

### 高级用法
#### DISTINCT 去重
```sql
SELECT AVG(DISTINCT prod_price) AS avg_price
FROM Products
WHERE vend_id = 'DLL01';
```
**限制**：
- 不可用于`COUNT(*)`
- 必须指定具体列名

#### 多函数组合
```sql
SELECT 
    COUNT(*) AS num_items,
    MIN(prod_price) AS price_min,
    MAX(prod_price) AS price_max,
    AVG(prod_price) AS price_avg
FROM Products;
```

### 参数说明
| 参数        | 作用范围               | 默认行为 |
|-------------|------------------------|----------|
| `ALL`       | 所有值（默认启用）     | 自动应用 |
| `DISTINCT`  | 仅处理不同值           | 需显式指定 |

> **关键记忆点**  
> 1. 所有聚集函数默认忽略NULL值（除COUNT(*)）  
> 2. DISTINCT可优化统计精度但增加计算开销  
> 3. 单SELECT语句可组合多个聚集函数实现综合统计

## 十、分组数据

### GROUP BY 基础语法
```sql
SELECT vend_id, COUNT(*) AS num_prods
FROM Products
GROUP BY vend_id;
```
**执行效果**：
```
BRS01 | 3
DLL01 | 4
FNG01 | 2
```

### 核心规则
1. **列选择限制**：
   - 必须包含在SELECT列表或有效表达式
   - 禁止使用聚集函数作为分组列
   - 不能使用字段别名

2. **数据分组特性**：
   - 支持多列嵌套分组（按最后指定的列汇总）
   - NULL值会单独成组
   - 禁止使用可变长度数据类型（如TEXT/BLOB）

3. **子句顺序**：
   ```sql
   SELECT ... FROM ... 
   WHERE ... 
   GROUP BY ... 
   HAVING ... 
   ORDER BY ...
   ```

### HAVING 分组过滤
```sql
-- 基础用法
SELECT cust_id, COUNT(*) AS orders
FROM Orders
GROUP BY cust_id
HAVING COUNT(*) >= 2;

-- 组合WHERE使用
SELECT vend_id, COUNT(*) AS num_prods
FROM Products
WHERE prod_price >= 4
GROUP BY vend_id
HAVING COUNT(*) >= 2;
```

### 排序分组结果
```sql
SELECT order_num, COUNT(*) AS items
FROM OrderItems
GROUP BY order_num
HAVING COUNT(*) >= 3
ORDER BY items, order_num;
```

### SELECT 子句执行顺序
| 子句       | 作用                 | 必需性 |
|------------|----------------------|--------|
| SELECT     | 返回列/表达式        | ✓      |
| FROM       | 数据来源表           | 表查询时✓ |
| WHERE      | 行级过滤             | ✕      |
| GROUP BY   | 分组设置             | 分组时✓ |
| HAVING     | 组级过滤             | ✕      |
| ORDER BY   | 结果排序             | ✕      |

### 特殊注意事项
1. **方言差异**：
   - SQL Server支持 `GROUP BY ALL`
   - 部分实现允许按列位置分组（如 `GROUP BY 2,1`）

2. **性能优化**：
   - WHERE在分组前过滤可提升效率
   - HAVING在分组后过滤会增加计算量

> **关键记忆点**  
> 1. GROUP BY与HAVING配合实现二级过滤  
> 2. 分组列必须原始存在（不可用别名/计算列）  
> 3. 排序操作始终最后执行

## 十一、使用子查询

### 基础概念
**子查询**：嵌套在其他查询中的查询语句，常用于WHERE子句和列计算

### WHERE子句嵌套
```sql
-- 单层嵌套
SELECT cust_id
FROM Orders
WHERE order_num IN (
    SELECT order_num
    FROM OrderItems
    WHERE prod_id = 'RGAN01'
);

-- 多层嵌套
SELECT cust_name, cust_contact
FROM Customers
WHERE cust_id IN (
    SELECT cust_id
    FROM Orders
    WHERE order_num IN (
        SELECT order_num
        FROM OrderItems
        WHERE prod_id = 'RGAN01'
    )
);
```

**关键限制**：
1. 子查询SELECT只能返回单个列
2. 嵌套层级理论上无限制（但实际受性能限制）
3. 不是最优执行方案（可能影响查询效率）

### 关联子查询
```sql
SELECT 
    cust_name,
    cust_state,
    (
        SELECT COUNT(*)
        FROM Orders
        WHERE Orders.cust_id = Customers.cust_id
    ) AS orders
FROM Customers
ORDER BY cust_name;
```
**执行特性**：
- 使用完全限定列名`表名.列名`明确作用域
- 对主查询每条记录执行一次子查询（示例中执行5次）

### 核心注意事项
| 要点                  | 说明                                                                 |
|-----------------------|----------------------------------------------------------------------|
| 表结构认知            | 必须清楚各表关联关系和字段分布                                       |
| 完全限定列名          | 多表操作时必须使用`表名.列名`格式                                    |
| 性能消耗              | 嵌套层级越深执行效率越低                                             |
| 列返回限制            | 子查询SELECT只能指定单列                                             |
| 错误排查              | 建议从最内层子查询开始逐步调试                                       |

### 应用场景总结
| 场景类型              | SQL示例片段                          |
|-----------------------|--------------------------------------|
| 条件过滤              | `WHERE col IN (SELECT...)`          |
| 数据存在性验证        | `WHERE EXISTS (SELECT...)`          |
| 动态列计算            | `SELECT (SELECT...) AS calculated`  |

> **开发建议**  
> 优先考虑使用JOIN替代多层嵌套子查询以提升性能，在必须使用子查询时应：
> 1. 限制嵌套层级（建议不超过3层）
> 2. 对关键字段建立索引
> 3. 使用EXPLAIN分析执行计划

## 十二、联结表

### 核心概念
**关系表**：  
将长信息分解为多个逻辑表，通过共同值互相关联的数据库设计范式

**联结**：  
表间关系的逻辑抽象，需在数据库设计阶段定义关联关系

### 基础联结语法
#### WHERE 等值联结
```sql
SELECT vend_name, prod_name, prod_price
FROM Vendors, Products
WHERE Vendors.vend_id = Products.vend_id;
```
**执行原理**：
- 笛卡尔积计算：将两表所有行组合（n*m 行）
- WHERE 过滤有效关联
- 未指定WHERE条件将产生全量组合（交叉联结）

#### INNER JOIN 标准语法
```sql
SELECT vend_name, prod_name, prod_price
FROM Vendors
INNER JOIN Products ON Vendors.vend_id = Products.vend_id;
```
**优势**：
- ANSI标准语法
- 更清晰的关联条件表达
- 支持复杂连接条件（如多列关联）

### 多表联结实践
```sql
SELECT 
    prod_name, 
    vend_name, 
    prod_price, 
    quantity
FROM OrderItems, Products, Vendors
WHERE Products.vend_id = Vendors.vend_id 
  AND OrderItems.prod_id = Products.prod_id
  AND order_num = 20007;
```
**表关系说明**：
1. OrderItems → Products（通过prod_id）
2. Products → Vendors（通过vend_id）

### 性能注意事项
| 要点                  | 说明                                                                 |
|-----------------------|----------------------------------------------------------------------|
| 关联表数量            | 避免联结不必要的表（建议不超过5表）                                 |
| DBMS限制              | 不同数据库对联结表数有不同限制                                      |
| 索引优化              | 关联字段应建立索引                                                  |
| 执行计划分析          | 复杂联结建议使用EXPLAIN分析                                         |

### 联结类型对比
| 语法类型        | 标准性       | 可读性 | 功能扩展性        |
|-----------------|-------------|--------|-------------------|
| WHERE等值联结   | 非标准       | 较低   | 仅支持简单等值联结 |
| INNER JOIN      | ANSI标准    | 高     | 支持复杂连接条件  |

> **开发建议**  
> 1. 优先使用INNER JOIN明确关联关系  
> 2. 多表关联时使用表别名提高可读性  
> 3. 关联字段数据类型必须严格匹配


## 十三、高级联结

### 核心概念
**关系表**：  
将长信息分解为多个逻辑表，通过共同值互相关联的数据库设计范式

**联结**：  
表间关系的逻辑抽象，需在数据库设计中明确关联方式

### 高级联结类型与示例

#### 1. 使用表别名缩短语句
```sql
SELECT cust_name, cust_contact
FROM Customers AS C, Orders AS O, OrderItems AS OI
WHERE C.cust_id = O.cust_id 
  AND OI.order_num = O.order_num 
  AND prod_id = 'RGAN01';
```
- **特性**：  
  表别名仅在查询执行中生效，不返回到客户端  
  Oracle 中需省略 `AS`，直接写 `Customers C`

#### 2. 自联结（Self-Join）
```sql
SELECT c1.cust_id, c1.cust_name, c1.cust_contact
FROM Customers AS c1, Customers AS c2
WHERE c1.cust_name = c2.cust_name 
  AND c2.cust_contact = 'Jim Jones';
```
- **用途**：  
  在同一表中关联不同行（如查找与 Jim Jones 同公司的其他职员）  
- **强制要求**：  
  必须使用表别名区分相同表

#### 3. 自然联结（Natural Join）
```sql
SELECT C.*, O.order_num, O.order_date, OI.prod_id, OI.quantity, OI.item_price
FROM Customers AS C, Orders AS O, OrderItems AS OI
WHERE C.cust_id = O.cust_id 
  AND OI.order_num = O.order_num 
  AND prod_id = 'RGAN01';
```
- **核心规则**：  
  通过 `WHERE` 过滤重复列，确保每列仅出现一次  
- **典型场景**：  
  标准内联结（Inner Join）默认是自然联结

#### 4. 外联结（Outer Join）
```sql
-- 左外联结（包含无订单顾客）
SELECT Customers.cust_id, Orders.order_num
FROM Customers
LEFT OUTER JOIN Orders 
  ON Customers.cust_id = Orders.cust_id;

-- 全外联结（部分数据库不支持）
SELECT Customers.cust_id, Orders.order_num
FROM Customers
FULL OUTER JOIN Orders 
  ON Customers.cust_id = Orders.cust_id;
```
- **方向说明**：  
  `LEFT`/`RIGHT` 指定主表（保留所有行）  
- **兼容性**：  
  MariaDB、MySQL、SQLite 不支持 `FULL OUTER JOIN`

#### 5. 联结与聚集函数结合
```sql
SELECT Customers.cust_id, COUNT(OrderItems.order_num) AS num_ord
FROM Customers
INNER JOIN Orders 
  ON Customers.cust_id = Orders.cust_id
GROUP BY Customers.cust_id;
```
- **作用**：  
  统计每个顾客的订单数量  

### 关键总结
1. **外联结**：常用场景为包含无关联行的查询（如未下单顾客）  
2. **自联结**：必须通过别名实现同一表的多次引用  
3. **自然联结**：通过主动排除重复列简化结果集  

## 十四、组合查询

### 基础语法
```sql
-- 基础UNION查询（自动去重）
SELECT cust_name, cust_contact, cust_email
FROM Customers
WHERE cust_state IN ('IL', 'IN', 'MI')
UNION
SELECT cust_name, cust_contact, cust_email
FROM Customers
WHERE cust_name = 'Fun4All'
ORDER BY cust_name, cust_contact;  -- 全局排序
```

### 关键规则
1. **列匹配要求**：
   - 每个SELECT必须包含相同数量的列
   - 对应列的数据类型需兼容（支持隐式转换）
   - 允许通过别名统一列名：
     ```sql
     SELECT name AS user_name, age FROM Students
     UNION
     SELECT emp_name, emp_age FROM Employees
     ```

2. **排序限制**：
   - 只能在整个UNION的最后使用一个ORDER BY
   - 排序作用于最终合并结果集

3. **去重特性**：
   - `UNION` 自动去重
   - `UNION ALL` 保留重复记录

### 性能对比
| 操作符        | 去重处理 | 执行效率 | 适用场景                 |
|---------------|----------|----------|--------------------------|
| `UNION`       | 自动去重 | 较低     | 需要唯一结果集           |
| `UNION ALL`   | 保留重复 | 较高     | 确认无重复或允许重复数据 |

### 注意事项
1. **复杂查询优化**：
   - 优先用UNION替代OR条件组合的复杂WHERE子句
   - 多层级UNION建议用括号明确优先级

2. **数据类型转换**：
   ```sql
   -- 示例：数值与文本列合并
   SELECT CAST(price AS VARCHAR) FROM Products
   UNION
   SELECT description FROM Inventory
   ```

3. **特殊场景处理**：
   ```sql
   -- 补充缺失列（用NULL填充）
   SELECT name, phone, email FROM Users
   UNION
   SELECT title, NULL, author FROM Books
   ```

> **开发建议**  
> 1. 明确业务需求选择UNION/UNION ALL  
> 2. 多表联合时优先保证列顺序一致  
> 3. 大数据量查询需注意内存消耗

## 十五、插入数据

### 基础插入语法
```sql
-- 全列插入（必须按表结构顺序）
INSERT INTO Customers 
VALUES(
    1000000006,
    'Toy Land',
    '123 Any Street',
    'New Work',
    'NY',
    '111111',
    'USA',
    NULL,
    NULL
);
```

### 显式列名插入（推荐）
```sql
-- 指定列名插入（允许省略可空列）
INSERT INTO Customers(
    cust_id,
    cust_name,
    cust_address,
    cust_city,
    cust_state,
    cust_zip,
    cust_country,
    cust_contact,
    cust_email
)
VALUES(
    1000000006,
    'Toy Land',
    '123 Any Street',
    'New Work',
    'NY',
    '111111',
    'USA',
    NULL,
    NULL
);
```

### 部分列插入
```sql
-- 插入部分列（依赖表约束）
INSERT INTO Customers(
    cust_id,
    cust_name,
    cust_address,
    cust_city,
    cust_state,
    cust_zip,
    cust_country
)
VALUES(
    1000000006,
    'Toy Land',
    '123 Any Street',
    'New Work',
    'NY',
    '111111',
    'USA'
);
```

### 批量插入
```sql
-- 从其他表导入数据
INSERT INTO Customers(
    cust_id,
    cust_name,
    cust_address,
    cust_city,
    cust_state,
    cust_zip,
    cust_country
)
SELECT 
    cust_id,
    cust_name,
    cust_address,
    cust_city,
    cust_state,
    cust_zip,
    cust_country
FROM CustNew;  -- 可添加WHERE过滤
```

### 表复制方法
#### 通用语法（部分DB不支持）
```sql
CREATE TABLE CustCopy AS 
SELECT * FROM Customers;  -- 可指定特定列
```

#### SQL Server专用语法
```sql
SELECT * INTO CustCopy 
FROM Customers;  -- 支持复杂查询和多表联结
```

### 关键注意事项
1. **列顺序**：
   - 全列插入必须严格匹配表结构顺序
   - 显式列名插入可任意顺序

2. **主键约束**：
   - 插入值不得与现有主键冲突
   - 主键列不可省略

3. **空值处理**：
   - 允许NULL的列可省略
   - 非空列必须提供值或定义默认值

4. **跨数据库差异**：
   | 操作              | DB2  | Oracle | SQL Server | MySQL |
   |-------------------|------|--------|------------|-------|
   | CREATE TABLE AS   | ❌   | ✔️     | ✔️         | ✔️    |
   | SELECT INTO       | ✔️   | ❌     | ✔️         | ❌    |

> **本章核心要点**  
> 1. 优先使用显式列名插入保证稳定性  
> 2. INSERT SELECT实现批量数据迁移  
> 3. 不同数据库表复制语法存在差异

## 十六、更新和删除数据

### 更新数据（UPDATE）
**基础语法**：
```sql
UPDATE Customers
SET cust_email = 'kim@thetoystore.com',
    cust_contact = 'Sam Roberts'
WHERE cust_id = 1000000005;
```

**核心规则**：
1. **WHERE子句必须**：  
   未指定WHERE条件将更新所有行
2. **多列更新**：  
   用逗号分隔多个 `列=值` 对
3. **子查询支持**：
   ```sql
   UPDATE Products
   SET price = (SELECT avg_price FROM PriceTable WHERE ...)
   WHERE prod_id = 'XLR01';
   ```

**扩展特性**：
- 部分DBMS支持 `FROM` 跨表更新：
  ```sql
  -- SQL Server示例
  UPDATE T1
  SET T1.col = T2.col
  FROM Table1 T1
  INNER JOIN Table2 T2 ON T1.id = T2.id
  ```

### 删除数据（DELETE）
**基础语法**：
```sql
DELETE FROM Customers
WHERE cust_id = 10000006;
```

**核心规则**：
1. **WHERE子句必须**：  
   未指定WHERE条件将删除所有行
2. **外键约束**：  
   关联数据存在时将阻止删除（如OrderItems引用被删产品）

### 注意事项
1. **数据保护**：
   - 操作前建议使用SELECT验证条件范围
   - 重要数据操作前进行备份

2. **事务控制**：
   ```sql
   BEGIN TRANSACTION;
   UPDATE ... -- 或 DELETE ...
   ROLLBACK;  -- 测试用回滚
   -- COMMIT; -- 确认后提交
   ```

3. **性能影响**：
   - 大规模更新/删除建议分批操作
   - 对频繁更新的字段建立索引

### 记
| 操作    | 关键命令               | 必要子句 | 风险点                  |
|---------|------------------------|----------|-------------------------|
| 更新    | `UPDATE SET WHERE`     | WHERE    | 误更新全表数据          |
| 删除    | `DELETE FROM WHERE`    | WHERE    | 误删除全表数据/外键约束 |

> **关键记忆**  
> 1. 所有UPDATE/DELETE必须包含精确的WHERE条件  
> 2. 重要操作前先用SELECT验证目标数据  
> 3. 关联数据删除需先处理子表再处理主表

## 十七、创建和操控表

### 创建表（CREATE TABLE）
**基础语法**：
```sql
CREATE TABLE Products (
    prod_id     CHAR(10)      NOT NULL,
    vend_id     CHAR(10)      NOT NULL,
    prod_name   CHAR(254)     NOT NULL,
    prod_price  DECIMAL(8,2)  NOT NULL,
    prod_desc   VARCHAR(1000) NULL
);
```
**核心规则**：
- 必须指定表名和列定义
- 列约束：
  - `NOT NULL`：禁止空值（默认允许NULL）
  - `DEFAULT`：设置默认值
  ```sql
  CREATE TABLE OrderItems (
      order_num    INTEGER      NOT NULL,
      order_item   INTEGER      NOT NULL,
      prod_id      CHAR(10)     NOT NULL,
      quantity     INTEGER      NOT NULL DEFAULT 1,
      item_price   DECIMAL(8,2) NOT NULL
  );
  ```

### 默认值时间函数
| DBMS         | 函数                  |
|--------------|-----------------------|
| DB2          | `CURRENT_DATE`        |
| MySQL        | `CURRENT_DATE()`      |
| Oracle       | `SYSDATE`             |
| PostgreSQL   | `CURRENT_DATE`        |
| SQL Server   | `GETDATE()`           |
| SQLite       | `date('now')`         |

### 修改表结构（ALTER TABLE）
**添加列**：
```sql
ALTER TABLE Vendors
ADD vend_phone CHAR(20);
```

**删除列**：
```sql
ALTER TABLE Vendors
DROP COLUMN vend_phone;  -- 部分DBMS不支持
```

**复杂结构修改步骤**：
1. 创建新表结构
2. 使用 `INSERT SELECT` 迁移数据
3. 验证新表数据完整性
4. 重命名旧表
5. 新表重命名为原表名
6. 重建索引/触发器等对象

### 删除表（DROP TABLE）
```sql
DROP TABLE CustCopy;  -- 不可逆操作
```

### 表重命名支持
| DBMS         | 语法                                  |
|--------------|---------------------------------------|
| DB2          | `RENAME TABLE old TO new`            |
| MariaDB      | `RENAME TABLE old TO new`            |
| MySQL        | `RENAME TABLE old TO new`            |
| Oracle       | `RENAME old TO new`                  |
| PostgreSQL   | `ALTER TABLE old RENAME TO new`      |
| SQL Server   | `EXEC sp_rename 'old', 'new'`         |
| SQLite       | `ALTER TABLE old RENAME TO new`      |

### 记
| 命令                | 作用                        | 注意事项                  |
|---------------------|-----------------------------|---------------------------|
| `CREATE TABLE`      | 创建新表结构                | 需预判未来需求            |
| `ALTER TABLE ADD`   | 增加新列                    | 受限数据类型/NULL约束     |
| `ALTER TABLE DROP`  | 删除指定列                  | 部分DBMS不支持            |
| `DROP TABLE`        | 永久删除整表                | 需关闭关联约束            |

> **关键记忆**  
> 1. 主键列必须为 `NOT NULL`  
> 2. 表结构修改前需备份数据  
> 3. 不同DBMS对DDL操作的支持差异较大

## 十八、使用视图

### 视图核心概念
- **本质**：存储的查询语句（不包含实际数据）
- **数据来源**：从基础表动态检索生成
- **核心特性**：
  - 重用复杂查询逻辑
  - 简化多表联结操作
  - 实现数据访问控制
  - 格式化输出数据

### 视图操作规范
| 规则类型        | 具体说明                                                                 |
|-----------------|--------------------------------------------------------------------------|
| 命名规则        | 必须唯一命名（不能与表同名）                                             |
| 权限要求        | 创建者需具备基础表的访问权限                                             |
| 嵌套限制        | 支持视图嵌套但影响性能                                                   |
| 排序限制        | 多数DBMS禁止在视图定义中使用ORDER BY                                     |
| 列命名要求      | 计算字段必须指定别名                                                     |
| 数据修改限制    | 通常作为只读对象（不能直接通过视图修改基础表）                           |

### 视图创建与使用
#### 基础视图（多表联结）
```sql
CREATE VIEW ProductsCustomers AS
SELECT cust_name, cust_contact, prod_id
FROM Customers, Orders, OrderItems
WHERE Customers.cust_id = Orders.cust_id
  AND OrderItems.order_num = Orders.order_num;

-- 视图使用示例
SELECT cust_name, cust_contact 
FROM ProductsCustomers
WHERE prod_id = 'RGAN01';
```

#### 格式化输出视图
```sql
-- SQL Server语法
CREATE VIEW VendorLocations AS
SELECT RTRIM(vend_name) + ' (' + RTRIM(vend_country) + ')' 
       AS vend_title
FROM Vendors;

-- PostgreSQL语法
CREATE VIEW VendorLocations AS
SELECT RTRIM(vend_name) || ' (' || RTRIM(vend_country) || ')' 
       AS vend_title
FROM Vendors;
```

#### 过滤数据视图
```sql
CREATE VIEW CustomerEMailList AS
SELECT cust_id, cust_name, cust_email
FROM Customers
WHERE cust_email IS NOT NULL;
```

#### 计算字段视图
```sql
CREATE VIEW OrderItemsExpanded AS
SELECT 
    order_num, 
    prod_id, 
    quantity, 
    item_price,
    quantity*item_price AS expanded_price
FROM OrderItems;
```

### 视图管理
```sql
-- 删除视图
DROP VIEW CustomerEMailList;
```

### 注意事项
1. **性能影响**：
   - 复杂视图嵌套会显著降低查询效率
   - 避免在频繁访问的场景使用多层视图

2. **跨平台差异**：
   | 特性                | SQL Server | Oracle | MySQL |
   |---------------------|------------|--------|-------|
   | 视图更新            | 有限支持   | 支持   | 不支持|
   | 索引支持            | 支持       | 支持   | 不支持|

> **开发建议**  
> 1. 优先使用视图封装复杂查询逻辑  
> 2. 对敏感数据字段进行访问控制  
> 3. 定期审查和优化视图性能

## 十九、使用存储过程

### 核心概念
- **定义**：预编译的SQL代码集合，类似函数封装
- **优势**：
  - 代码复用与模块化
  - 提升复杂操作性能
  - 增强数据安全性
- **局限**：不同DBMS语法差异大，可移植性差

### 基础语法示例
#### 调用存储过程
```sql
-- 通用调用语法（参数顺序传递）
EXECUTE AddNewProduct(
    'JTS01',
    'Stuffed Eiffel Tower',
    6.49,
    'Plush stuffed toy with the text La Tour Eiffel in red white and blue'
);
```

### Oracle实现
#### 创建存储过程
```sql
CREATE PROCEDURE MailingListCount(
    ListCount OUT INTEGER
)
IS
v_rows INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_rows
    FROM Customers
    WHERE cust_email IS NOT NULL;
    ListCount := v_rows;
END;
```
**参数类型**：
- `IN`：输入参数（默认）
- `OUT`：输出参数
- `INOUT`：双向参数

#### 调用存储过程
```sql
-- 声明变量接收返回值
var ReturnValue NUMBER
EXEC MailingListCount(:ReturnValue);
SELECT ReturnValue;
```

### SQL Server实现
#### 创建无参存储过程
```sql
CREATE PROCEDURE MailingListCount
AS
DECLARE @cnt INTEGER
SELECT @cnt = COUNT(*)
FROM Customers
WHERE cust_email IS NOT NULL;
RETURN @cnt;
```

#### 调用并获取返回值
```sql
DECLARE @ReturnValue INT
EXECUTE @ReturnValue = MailingListCount;
SELECT @ReturnValue;
```

#### 带事务的存储过程
```sql
CREATE PROCEDURE NewOrder 
    @cust_id CHAR(10)
AS
DECLARE @order_num INTEGER
-- 获取当前最大订单号
SELECT @order_num = MAX(order_num) FROM Orders
-- 生成新订单号
SET @order_num = @order_num + 1
-- 插入新订单
INSERT INTO Orders(order_num, order_date, cust_id)
VALUES(@order_num, GETDATE(), @cust_id)
-- 返回生成的订单号
RETURN @order_num;

-- 简化版（使用标识字段）
CREATE PROCEDURE NewOrder 
    @cust_id CHAR(10)
AS
INSERT INTO Orders(cust_id)
VALUES(@cust_id)
-- 返回自动生成的订单号
SELECT order_num = @@IDENTITY;
```

### 参数传递方式
| 传递方式        | 说明                          | 示例                    |
|-----------------|-------------------------------|-------------------------|
| 位置顺序传递    | 按参数声明顺序传递            | `EXEC Proc1 'A', 100`   |
| 命名参数传递    | 指定参数名传递（部分DB支持）  | `EXEC Proc1 @p1='A'`    |

### 注意事项
1. **性能优化**：
   - 避免在存储过程中嵌套复杂查询
   - 对频繁访问的存储过程建立执行计划缓存

2. **事务管理**：
   ```sql
   BEGIN TRANSACTION
   -- 业务逻辑
   IF @@ERROR <> 0
       ROLLBACK TRANSACTION
   ELSE
       COMMIT TRANSACTION
   ```

3. **跨平台差异**：
   | 特性              | Oracle          | SQL Server       |
   |-------------------|-----------------|------------------|
   | 参数前缀          | 无              | @                |
   | 返回值关键字      | RETURN          | RETURN/OUTPUT    |
   | 自动递增字段获取  | RETURNING INTO  | @@IDENTITY       |

> **开发建议**  
> 1. 重要存储过程需包含异常处理机制  
> 2. 参数命名建议采用@+驼峰格式（如@CustomerId）  
> 3. 修改表结构后需重新编译关联存储过程

## 二十、管理事务处理

### 核心概念
- **事务处理**：确保批处理的SQL操作完全执行或完全不执行，维护数据库完整性
- **关键机制**：
  - 显式提交（COMMIT）确认操作
  - 回退（ROLLBACK）撤销未提交操作
  - 保存点（SAVEPOINT）实现部分回滚

### 事务控制语法（DBMS差异）
| 操作               | SQL Server         | MySQL/MariaDB     | Oracle            | PostgreSQL        |
|--------------------|--------------------|-------------------|-------------------|-------------------|
| 开始事务           | `BEGIN TRANSACTION`| `START TRANSACTION`| `SET TRANSACTION` | `BEGIN`           |
| 提交事务           | `COMMIT TRANSACTION`| `COMMIT`          | `COMMIT`          | `COMMIT`          |
| 回滚事务           | `ROLLBACK TRANSACTION` | `ROLLBACK`   | `ROLLBACK`        | `ROLLBACK`        |
| 创建保存点         | `SAVE TRANSACTION <name>` | `SAVEPOINT <name>` | `SAVEPOINT <name>` | `SAVEPOINT <name>` |
| 回滚到保存点       | `ROLLBACK TRANSACTION <name>` | `ROLLBACK TO <name>` | `ROLLBACK TO <name>` | `ROLLBACK TO SAVEPOINT <name>` |

### 基础操作示例
#### 回退操作
```sql
-- 通用语法
DELETE FROM Orders;
ROLLBACK;
```

#### 显式提交事务
```sql
-- SQL Server实现
BEGIN TRANSACTION
    DELETE OrderItems WHERE order_num = 12345
    DELETE Orders WHERE order_num = 12345
COMMIT TRANSACTION

-- Oracle实现
SET TRANSACTION
    DELETE OrderItems WHERE order_num = 12345;
    DELETE Orders WHERE order_num = 12345;
COMMIT;
```

### 保存点应用
```sql
-- MySQL/MariaDB/Oracle
SAVEPOINT delete1;
-- 后续操作...
ROLLBACK TO delete1;

-- SQL Server
SAVE TRANSACTION delete1;
-- 后续操作...
ROLLBACK TRANSACTION delete1;
```

### 完整事务示例（SQL Server）
```sql
BEGIN TRANSACTION
    -- 插入客户数据
    INSERT INTO Customers(cust_id, cust_name)
    VALUES(1000000010, 'Toys Emporium')
    
    -- 创建保存点
    SAVE TRANSACTION StartOrder;
    
    -- 插入订单头
    INSERT INTO Orders(order_num, order_date, cust_id)
    VALUES(20100, '2001/12/1', 1000000010);
    
    -- 错误检测1
    IF @@ERROR <> 0 
        ROLLBACK TRANSACTION StartOrder;
    
    -- 插入订单明细1
    INSERT INTO OrderItems(order_num, order_item, prod_id, quantity, item_price)
    VALUES(20100, 1, 'BR01', 100, 5.49);
    
    -- 错误检测2
    IF @@ERROR <> 0 
        ROLLBACK TRANSACTION StartOrder;
    
    -- 插入订单明细2
    INSERT INTO OrderItems(order_num, order_item, prod_id, quantity, item_price)
    VALUES(20100, 2, 'BR03', 100, 10.99);
    
    -- 错误检测3
    IF @@ERROR <> 0 
        ROLLBACK TRANSACTION StartOrder;

COMMIT TRANSACTION
```

### 关键要点
1. **原子性保证**：事务内的操作要么全部成功，要么全部撤销
2. **错误处理**：
   - SQL Server使用`@@ERROR`系统函数检测错误
   - 其他DBMS可能使用`SQLSTATE`或异常捕获机制
3. **生产环境建议**：
   - 重要操作必须包含事务控制
   - 事务范围不宜过大（避免长事务锁资源）
   - 保存点适用于多步骤业务场景

> **注**：实际开发前需查阅目标数据库的官方事务文档

## 二十一、使用游标

### 核心概念
- **游标定义**：存储在DBMS服务器上的查询结果集，用于逐行处理数据
- **核心功能**：
  - 实现数据结果集的逐行访问
  - 支持结果集的前后滚动
  - 允许对特定行进行修改
- **适用场景**：
  - 需要逐行处理的交互式应用
  - 复杂业务逻辑中的分步数据操作

### 游标操作步骤
1. **声明游标**：定义结果集结构和游标属性
2. **打开游标**：执行关联查询并填充数据
3. **检索数据**：逐行/批量获取结果集数据
4. **关闭游标**：释放系统资源（可重新打开）
5. **释放游标**：彻底删除游标对象（部分DBMS需要）

### 不同DBMS语法对比
| 操作         | DB2/MySQL/SQL Server                          | Oracle/PostgreSQL                          |
|--------------|-----------------------------------------------|--------------------------------------------|
| 声明游标     | `DECLARE CustCursor CURSOR FOR [SELECT...]`   | `DECLARE CURSOR CustCursor IS [SELECT...]` |
| 打开游标     | `OPEN CURSOR CustCursor`                      | `OPEN CustCursor`                          |
| 关闭游标     | `CLOSE CustCursor`                            | 同左                                       |

### 基础操作示例
#### 声明与打开
```sql
-- DB2/MySQL/SQL Server
DECLARE CustCursor CURSOR
FOR
SELECT * FROM Customers
WHERE cust_email IS NULL;

-- Oracle/PostgreSQL
DECLARE CURSOR CustCursor
IS
SELECT * FROM Customers
WHERE cust_email IS NULL;

-- 通用打开操作
OPEN CustCursor;
```

#### 检索数据
```sql
-- Oracle示例
DECLARE 
    TYPE CustCursor IS REF CURSOR 
        RETURN Customers%ROWTYPE;
    CustRecord Customers%ROWTYPE;
BEGIN
    OPEN CustCursor;
    FETCH CustCursor INTO CustRecord; -- 获取单行
    CLOSE CustCursor;
END;
```

#### 循环检索
```sql
-- Oracle循环示例
DECLARE 
    TYPE CustCursor IS REF CURSOR 
        RETURN Customers%ROWTYPE;
    CustRecord Customers%ROWTYPE;
BEGIN
    OPEN CustCursor;
    LOOP
        FETCH CustCursor INTO CustRecord;
        EXIT WHEN CustCursor%NOTFOUND; -- 无数据时退出循环
        -- 业务处理逻辑
    END LOOP;
    CLOSE CustCursor;
END;
```

### 高级控制
#### 游标属性（Oracle示例）
| 属性              | 描述                          |
|-------------------|-------------------------------|
| `%ISOPEN`         | 游标是否打开                  |
| `%FOUND`          | 最近FETCH是否返回行           |
| `%NOTFOUND`       | 最近FETCH是否未返回行         |
| `%ROWCOUNT`       | 已检索的行数                  |

### 注意事项
1. **资源管理**：
   - 必须显式关闭已打开的游标
   - 避免长期持有游标（防止资源锁定）

2. **性能影响**：
   - 游标操作比集合操作效率低
   - 大数据集优先考虑集合操作

3. **兼容性差异**：
   | 特性                | SQL Server         | Oracle           |
   |---------------------|--------------------|------------------|
   | 可更新游标          | 支持               | 支持             |
   | 敏感游标            | 支持               | 通过`FOR UPDATE` |
   | 自动滚动            | 需指定`SCROLL`选项 | 默认支持         |

> **关键记忆**  
> 游标五步法：声明 → 打开 → 检索 → 关闭 → 释放  
> 始终在完成操作后关闭游标释放资源

## 二十二、高级SQL特性

### 约束管理

#### 主键约束
**作用**：唯一标识表中的每一行
```sql
-- 创建表时定义主键
CREATE TABLE Vendors (
    vend_id CHAR(10) NOT NULL PRIMARY KEY,
    vend_name CHAR(50) NOT NULL
);

-- 修改表添加主键
ALTER TABLE Vendors
ADD CONSTRAINT PK_Vendors PRIMARY KEY (vend_id);
```

#### 外键约束
**作用**：确保引用完整性
```sql
-- 创建表时定义外键
CREATE TABLE Orders (
    order_num INTEGER NOT NULL PRIMARY KEY,
    cust_id CHAR(10) NOT NULL REFERENCES Customers(cust_id)
);

-- 修改表添加外键
ALTER TABLE Orders
ADD CONSTRAINT FK_Orders_Customers 
FOREIGN KEY (cust_id) REFERENCES Customers(cust_id);
```

#### 唯一约束
| 对比项        | 主键               | 唯一约束           |
|--------------|--------------------|--------------------|
| 数量限制      | 每表1个            | 每表多个           |
| NULL值        | 不允许             | 允许               |
| 外键关联      | 可作外键           | 不可作外键         |
| 修改规则      | 不可修改           | 允许修改           |
```sql
CREATE TABLE Employees (
    emp_id INT UNIQUE,
    email VARCHAR(100) UNIQUE
);
```

#### 检查约束
**作用**：确保列值符合指定条件
```sql
CREATE TABLE OrderItems (
    quantity INT NOT NULL CHECK (quantity > 0),
    item_price DECIMAL(10,2) CHECK (item_price >= 0)
);
```

### 索引优化
**核心作用**：
- 加速数据检索
- 优化排序和过滤

**使用原则**：<br>
✔️ 频繁查询的列  
✔️ 常作为JOIN条件的列  
❌ 数据变更频繁的列  
❌ 数据差异性低的列

```sql
-- 创建单列索引
CREATE INDEX idx_prod_name 
ON Products(prod_name);

-- 创建复合索引
CREATE INDEX idx_name_price
ON Products(prod_name, prod_price);
```

### 触发器机制
**主要功能**：
- 数据一致性保障
- 自动审计追踪
- 业务规则实施

#### SQL Server实现
```sql
CREATE TRIGGER trg_uppercase_state
ON Customers
AFTER INSERT, UPDATE
AS
BEGIN
    UPDATE C
    SET cust_state = UPPER(cust_state)
    FROM Customers C
    INNER JOIN inserted i ON C.cust_id = i.cust_id
END;
```

#### Oracle/PostgreSQL实现
```sql
CREATE TRIGGER trg_uppercase_state
AFTER INSERT OR UPDATE ON Customers
FOR EACH ROW
BEGIN
    :NEW.cust_state := UPPER(:NEW.cust_state);
END;
```

### 记
| 特性        | 关键实现方式                     | 典型应用场景         |
|-------------|----------------------------------|----------------------|
| 主键约束    | `PRIMARY KEY`                   | 唯一标识记录         |
| 外键约束    | `FOREIGN KEY REFERENCES`       | 维护表间关系完整性    |
| 唯一约束    | `UNIQUE`                        | 确保列值唯一性       |
| 检查约束    | `CHECK`                         | 实施业务规则         |
| 索引        | `CREATE INDEX`                  | 加速数据检索         |
| 触发器      | `CREATE TRIGGER`                | 自动化数据操作       |

> **开发建议**  
> 1. 主键应使用无意义代理键（如自增ID）  
> 2. 外键约束需配套设计级联操作规则  
> 3. 索引创建需平衡查询性能与写入开销

## MySQL 基本使用补充

### 系统信息查询
```sql
-- 查看表结构
SHOW COLUMNS FROM customers;

-- 显示服务器状态和配置
SHOW STATUS;        -- 服务器运行状态
SHOW VARIABLES;     -- 系统变量配置

-- 查看创建语句
SHOW CREATE DATABASE db_name;  -- 显示数据库创建语句
SHOW CREATE TABLE tbl_name;     -- 显示表创建语句

-- 权限与进程管理
SHOW GRANTS;                   -- 显示用户权限
SHOW GRANTS FOR user@host;     -- 查看指定用户权限
SHOW PROCESSLIST;              -- 显示活动进程
KILL process_id;               -- 终止指定进程（需替换process_id）

-- 错误与警告
SHOW ERRORS;    -- 显示最近错误信息
SHOW WARNINGS;  -- 显示最近警告信息
```

## MySQL 正则表达式

### 基础使用
```sql
-- 正则匹配（默认不区分大小写）
SELECT prod_name
FROM products
WHERE prod_name REGEXP '1000'
ORDER BY prod_name;

-- 区分大小写匹配
SELECT prod_name
FROM products
WHERE prod_name REGEXP BINARY 'JetPack'
```

### 正则符号详解

#### 基础匹配
| 模式       | 说明                          | 示例            |
|------------|-------------------------------|-----------------|
| `.`        | 匹配任意单个字符               | `.000` 匹配 "A000"、"1000" |
| `|`        | 或逻辑匹配                     | `1000|2000` 匹配包含这两个值的记录 |
| `[]`       | 匹配括号内任意字符             | `[123]` 匹配 "1"、"2"、"3" |
| `[^]`      | 匹配不在括号内的字符           | `[^123]` 匹配非1/2/3的字符 |
| `[0-9]`    | 匹配数字范围                   | `[3-6]` 匹配3-6之间的数字 |
| `\\`       | 转义特殊字符                   | `\\.` 匹配字面量"." |

#### 量词控制
| 模式       | 说明                          | 示例            |
|------------|-------------------------------|-----------------|
| `*`        | 0次或多次匹配                  | `a*` 匹配空、"a"、"aa" |
| `+`        | 1次或多次匹配                  | `a+` 匹配 "a"、"aa" |
| `?`        | 0次或1次匹配                   | `a?` 匹配空、"a" |
| `{n}`      | 精确n次匹配                    | `a{3}` 匹配 "aaa" |
| `{n,}`     | 至少n次匹配                    | `a{2,}` 匹配 "aa"、"aaa" |
| `{n,m}`    | 范围次数匹配                   | `a{2,4}` 匹配 "aa"、"aaa"、"aaaa" |

#### 定位符
| 模式           | 说明                          | 示例            |
|----------------|-------------------------------|-----------------|
| `^`            | 匹配文本开始位置               | `^a` 匹配以a开头的字符串 |
| `$`            | 匹配文本结束位置               | `a$` 匹配以a结尾的字符串 |
| `[[:<:]]`      | 单词起始边界                   | `[[:<:]]code` 匹配 "code" 开头的单词 |
| `[[:>:]]`      | 单词结束边界                   | `end[[:>:]]` 匹配以 "end" 结尾的单词 |

#### 预定义字符集
| 模式           | 等效表达式       | 说明                |
|----------------|------------------|---------------------|
| `[:alnum:]`    | `[a-zA-Z0-9]`    | 字母数字字符        |
| `[:alpha:]`    | `[a-zA-Z]`       | 字母字符            |
| `[:digit:]`    | `[0-9]`          | 数字字符            |
| `[:lower:]`    | `[a-z]`          | 小写字母            |
| `[:upper:]`    | `[A-Z]`          | 大写字母            |

> **正则与LIKE关键区别**  
> 1. 正则执行子串匹配（如`'1000'`可匹配"X1000Y"）  
> 2. LIKE需要完全匹配（除非使用通配符）  
> 3. 正则更适用于复杂模式匹配场景

## MySQL 全文本搜索

### 存储引擎支持
- **MyISAM**：支持全文本搜索
- **InnoDB**：不支持全文本搜索

### 创建全文本索引
```sql
CREATE TABLE productnotes (
    note_id INT NOT NULL AUTO_INCREMENT,
    note_text TEXT NULL,
    PRIMARY KEY(note_id),
    FULLTEXT(note_text)  -- 单列全文本索引
) ENGINE=MyISAM;

-- 多列全文本索引示例
CREATE TABLE articles (
    id INT NOT NULL AUTO_INCREMENT,
    title VARCHAR(200),
    content TEXT,
    PRIMARY KEY(id),
    FULLTEXT(title, content)
) ENGINE=MyISAM;
```

### 基础全文本搜索
```sql
SELECT note_text
FROM productnotes
WHERE MATCH(note_text) AGAINST('rabbit');
```
**特性**：
- `MATCH()` 指定被索引的列
- `AGAINST()` 指定搜索表达式
- 搜索结果按相关性自动排序（包含搜索词的位置越靠前，排名越高）

### 查看搜索排名权重
```sql
SELECT note_text, 
       MATCH(note_text) AGAINST('rabbit') AS rank
FROM productnotes;
```
**排名规则**：
- 基于词频、唯一词数量、索引总词数和包含词的文档数量计算

### 查询扩展模式
```sql
SELECT note_text
FROM productnotes
WHERE MATCH(note_text) AGAINST('anvils' WITH QUERY EXPANSION);
```
**工作原理**：
1. 执行首次搜索匹配相关行
2. 提取结果中的关键词进行二次扩展搜索

### 布尔搜索模式
```sql
SELECT note_text
FROM productnotes
WHERE MATCH(note_text) AGAINST('heavy -rope*' IN BOOLEAN MOOE);
```
**布尔操作符**：
| 操作符 | 功能说明                          | 示例               |
|--------|----------------------------------|--------------------|
| `+`    | 必须包含                         | `+apple`           |
| `-`    | 必须排除                         | `-banana`          |
| `>`    | 提高词权重                       | `>orange`          |
| `<`    | 降低词权重                       | `<pear`            |
| `()`   | 组合表达式                        | `(hot AND coffee)` |
| `~`    | 否定词权重                       | `~berry`           |
| `*`    | 通配符（词尾模糊匹配）            | `nut*`             |
| `""`   | 精确短语匹配                      | `"fresh juice"`    |

### 特殊说明
- 全文本搜索自动忽略英文单引号：`don't` 会按 `dont` 处理
- 默认最小词长为4字符（可通过`ft_min_word_len`配置修改）
- 停用词列表中的词会被自动忽略（如"the"、"and"等）

## MySQL 存储过程补充

### 存储过程调用
```sql
-- 调用存储过程并传递输出参数
CALL productpricing(@pricelow, @pricehigh, @priceaverage);
```

**说明**：
- 使用`CALL`关键字执行存储过程
- `@`符号表示用户定义变量，用于接收输出参数
- 参数类型需与存储过程定义匹配

### 存储过程创建（带输出参数）
```sql
DELIMITER //  -- 修改分隔符避免冲突

CREATE PROCEDURE productpricing(
    OUT p1 DECIMAL(8,2),    -- 最低价输出参数
    OUT ph DECIMAL(8,2),    -- 最高价输出参数
    OUT pa DECIMAL(8,2)     -- 平均价输出参数
)
BEGIN
    SELECT MIN(prod_price) INTO p1 FROM products;
    SELECT MAX(prod_price) INTO ph FROM products;
    SELECT AVG(prod_price) INTO pa FROM products;
END //

DELIMITER ;  -- 恢复默认分隔符
```

**参数类型说明**：
| 类型        | 作用                          |
|-------------|-------------------------------|
| `IN`        | 输入参数（默认）              |
| `OUT`       | 输出参数                      |
| `INOUT`     | 输入输出双重作用              |

**完整使用示例**：
```sql
-- 1. 调用存储过程
CALL productpricing(@low_price, @high_price, @avg_price);

-- 2. 查询结果
SELECT @low_price AS lowest_price, 
       @high_price AS highest_price,
       @avg_price AS average_price;
```

### 存储过程特性
1. **变量作用域**：
   - 用户变量（@开头）会话级有效
   - 局部变量需用`DECLARE`声明（仅在BEGIN/END块内有效）

2. **错误处理**：
   ```sql
   DECLARE EXIT HANDLER FOR SQLEXCEPTION
   BEGIN
       ROLLBACK;
       SELECT 'Error occurred' AS message;
   END;
   ```

3. **事务控制**：
   ```sql
   START TRANSACTION;
   -- 业务逻辑
   IF @@ERROR_COUNT = 0 THEN
       COMMIT;
   ELSE 
       ROLLBACK;
   END IF;
   ```

> **最佳实践**  
> 1. 始终使用`DELIMITER`修改分隔符创建存储过程  
> 2. 对输出参数使用描述性命名（如@min_price）  
> 3. 重要操作包含错误处理和事务控制

## MySQL 触发器补充

### 触发器基础操作
```sql
-- 创建触发器
CREATE TRIGGER newproduct 
AFTER INSERT ON products
FOR EACH ROW 
    SELECT 'Product added' AS notification;

-- 删除触发器
DROP TRIGGER newproduct;
```

**创建规则**：
- 每个表每个事件（INSERT/UPDATE/DELETE）仅允许1个触发器
- 最多支持6个触发器（3事件 × BEFORE/AFTER）
- 触发器必须关联具体表

### 触发器类型与应用

#### INSERT 触发器
```sql
CREATE TRIGGER neworder 
AFTER INSERT ON orders
FOR EACH ROW 
    SELECT NEW.order_num AS generated_order_id;
```
**虚拟表特性**：
- 访问新插入数据：`NEW` 表
- 自动增量字段：INSERT前`NEW.auto_col=0`，INSERT后为生成值
- BEFORE INSERT时可修改`NEW`值

#### DELETE 触发器
```sql
CREATE TRIGGER deleteorder 
BEFORE DELETE ON orders
FOR EACH ROW
BEGIN
    INSERT INTO archive_orders(order_num, order_date, cust_id)
    VALUES(OLD.order_num, OLD.order_date, OLD.cust_id);
END;
```
**虚拟表特性**：
- 访问被删除数据：`OLD` 表
- 所有字段只读不可修改

#### UPDATE 触发器
```sql
CREATE TRIGGER updateorder 
BEFORE UPDATE ON orders
FOR EACH ROW 
    SET NEW.vend_state = UPPER(NEW.vend_state);
```
**虚拟表特性**：
| 表名   | 数据内容                | 可修改性 |
|--------|-------------------------|----------|
| `OLD`  | 更新前的原始数据        | 只读     |
| `NEW`  | 将要更新的新数据        | 可修改   |

### 虚拟表权限对照
| 操作类型 | 触发时机 | 可用虚拟表 | 修改权限           |
|----------|----------|------------|--------------------|
| INSERT   | BEFORE   | NEW        | ✔️ 可修改插入值    |
| INSERT   | AFTER    | NEW        | ❌ 仅查看         |
| DELETE   | BEFORE   | OLD        | ❌ 只读           |
| DELETE   | AFTER    | OLD        | ❌ 只读           |
| UPDATE   | BEFORE   | OLD/NEW    | OLD只读，NEW可修改 |
| UPDATE   | AFTER    | OLD/NEW    | ❌ 只读           |

### 应用场景建议
1. **数据审计**：自动记录删除/修改历史
2. **数据校验**：BEFORE触发时验证业务规则
3. **格式统一**：强制字段标准化（如大小写转换）
4. **级联操作**：同步更新关联表数据

> **注意事项**  
> 1. 避免在触发器中编写复杂业务逻辑  
> 2. 谨慎处理递归触发场景  
> 3. 修改表结构后需重建关联触发器

## MySQL 事务处理补充

### 事务支持说明
| 存储引擎   | 事务支持 | 自动提交默认状态 |
|------------|----------|------------------|
| MyISAM     | ❌       | 始终自动提交     |
| InnoDB     | ✔️       | 自动提交开启     |

**基础事务控制**：
```sql
-- 关闭自动提交（仅当前会话有效）
SET autocommit = 0;

-- 显式开启事务
START TRANSACTION;

-- 提交事务（持久化更改）
COMMIT;

-- 回滚事务（撤销未提交操作）
ROLLBACK;
```

## MySQL 字符集与校对规则

### 字符集管理
**查看可用字符集**：
```sql
SHOW CHARACTER SET;
-- 示例输出：
-- | utf8mb4 | UTF-8 Unicode | utf8mb4_0900_ai_ci |      4 |
```

**查看校对规则**：
```sql
SHOW COLLATION LIKE 'utf8mb4%';
-- 示例输出：
-- | utf8mb4_0900_ai_ci | utf8mb4 | 255 | Yes | Yes | 1 |
```

### 表级字符集设置
```sql
CREATE TABLE mytable (
    column1 INT,
    column2 VARCHAR(10)
) DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;
```
**参数说明**：
- `CHARACTER SET`：指定默认字符集（建议使用utf8mb4兼容emoji）
- `COLLATE`：指定排序规则（如`utf8mb4_0900_ai_ci`表示不区分大小写的Unicode 9.0标准排序）

### 列级字符集设置
```sql
CREATE TABLE mytable (
    name VARCHAR(50) CHARACTER SET latin1 COLLATE latin1_general_cs
);
```
**特性**：
- 支持为不同列指定不同字符集
- `COLLATE`后缀说明：
  - `ci`：大小写不敏感（Case Insensitive）
  - `cs`：大小写敏感（Case Sensitive）
  - `bin`：二进制比较

### 最佳实践建议
1. **统一字符集**：
   - 推荐全库使用`utf8mb4`字符集
   - 校对规则根据业务需求选择（如需要区分大小写选择`utf8mb4_bin`）

2. **连接设置**：
   ```sql
   SET NAMES 'utf8mb4';  -- 设置客户端连接字符集
   ```

3. **字符集转换**：
   ```sql
   ALTER TABLE mytable CONVERT TO CHARACTER SET utf8mb4;
   ```

> **注意**  
> 修改已有数据的字符集可能引起数据损坏，操作前务必做好备份

## MySQL 安全管理

### 用户账号管理
```sql
-- 查看所有用户账号
SELECT user FROM mysql.user;

-- 创建用户（需指定密码）
CREATE USER 'ben' IDENTIFIED BY 'p@$$w0rd';

-- 重命名用户（MySQL 5.0+）
RENAME USER 'ben' TO 'bforta';

-- 删除用户
DROP USER 'bforta';
```

### 权限管理
```sql
-- 授予SELECT权限（数据库级）
GRANT SELECT ON crashcourse.* TO 'bforta';

-- 授予多权限（表级）
GRANT SELECT, INSERT ON crashcourse.orders TO 'bforta';

-- 撤销权限
REVOKE SELECT ON crashcourse.* FROM 'bforta';
```

### 权限层级控制
| 层级                  | 语法示例                         | 说明                     |
|-----------------------|----------------------------------|--------------------------|
| 全局权限              | `GRANT ALL ON *.*`               | 影响所有数据库/表        |
| 数据库级              | `GRANT SELECT ON database.*`     | 控制整个数据库           |
| 表级                  | `GRANT UPDATE ON database.table` | 控制特定表               |
| 列级                  | `GRANT SELECT(col1) ON table`    | 精确到列（需逐列指定）   |
| 存储过程              | `GRANT EXECUTE ON PROCEDURE`     | 控制存储过程执行权限     |

### 密码管理
```sql
-- 修改其他用户密码（需权限）
SET PASSWORD FOR 'bforta' = PASSWORD('n3w p@$$w0rd');

-- 修改当前用户密码
SET PASSWORD = PASSWORD('n3w p@$$w0rd');

-- 推荐使用更安全的认证方式（MySQL 8.0+）
ALTER USER 'bforta' IDENTIFIED WITH mysql_native_password BY 'new_password';
```

### 最佳实践
1. **最小权限原则**：仅授予必要权限
2. **定期审计权限**：`SHOW GRANTS FOR user`
3. **密码复杂度要求**：至少包含大小写字母、数字、特殊符号
4. **权限生效**：执行 `FLUSH PRIVILEGES;` 使权限修改立即生效

> **重要说明**  
> - `PASSWORD()` 函数在 MySQL 5.7.6+ 已弃用，建议使用 `ALTER USER` 语法  
> - MySQL 8.0+ 默认使用 `caching_sha2_password` 认证插件，需客户端适配

## MySQL 数据维护

### 数据备份与恢复
| 方法                  | 命令/语法                          | 说明                                                                 |
|-----------------------|------------------------------------|----------------------------------------------------------------------|
| mysqldump            | `mysqldump -u user -p dbname > backup.sql` | 全库/单库逻辑备份（生成SQL文件）                                    |
| mysqlhotcopy         | `mysqlhotcopy dbname /backup/path`        | 物理备份工具（仅限MyISAM表，需要服务器权限）                         |
| BACKUP TABLE         | `BACKUP TABLE tbl1, tbl2 TO '/backup'`    | 单表备份（需要FILE权限）                                            |
| SELECT INTO OUTFILE  | `SELECT * INTO OUTFILE '/backup/data.txt' FROM tbl` | 导出数据到文本文件                                                  |
| RESTORE TABLE       | `RESTORE TABLE tbl FROM '/backup'`        | 从备份恢复表                                                        |

### 表维护操作
#### 表状态检查
```sql
-- 检查表结构完整性
ANALYZE TABLE orders;

-- 多表检查（MyISAM验证索引）
CHECK TABLE orders, orderitems;

-- 不同检查模式
CHECK TABLE tbl_name FAST;    -- 快速检查未正常关闭的表
CHECK TABLE tbl_name MEDIUM;  -- 检查删除链接并验证键
CHECK TABLE tbl_name EXTENDED;-- 最彻底检查
```

#### 表修复与优化
```sql
-- 修复损坏表（MyISAM专用）
REPAIR TABLE damaged_table;

-- 回收存储空间（InnoDB/MyISAM）
OPTIMIZE TABLE large_table; 

-- 强制修复（高风险操作）
myisamchk --recover /var/lib/mysql/dbname/tbl_name.MYI
```

### 日志管理
#### 日志类型控制
| 启动参数             | 日志文件位置              | 说明                               |
|----------------------|--------------------------|------------------------------------|
| `--log-error=name`   | `/var/log/mysql/name.err` | 错误日志（默认主机名.err）         |
| `--log=name`         | `/var/log/mysql/name.log` | 通用查询日志                       |
| `--log-bin=name`     | `/var/lib/mysql/name-bin` | 二进制日志（记录数据变更操作）     |

#### 日志维护命令
```sql
-- 刷新所有日志文件
FLUSH LOGS;

-- 清理二进制日志
PURGE BINARY LOGS TO 'mysql-bin.010';
```

### 服务器诊断选项
| 启动参数          | 功能说明                                                                 |
|-------------------|--------------------------------------------------------------------------|
| `--help`          | 显示所有配置选项                                                         |
| `--safe-mode`     | 安全模式启动（跳过某些优化配置）                                         |
| `--verbose`       | 显示详细启动信息（配合`--help`使用）                                     |
| `--version`       | 显示版本信息后退出                                                       |

### 维护最佳实践
1. **定期备份策略**：
   - 生产环境建议每天全量备份 + 每小时二进制日志增量备份
   - 验证备份文件完整性：`mysqlcheck --all-databases`

2. **空间回收时机**：
   - 执行大量DELETE操作后立即运行`OPTIMIZE TABLE`
   - 表文件异常增长时检查碎片率：`SHOW TABLE STATUS LIKE 'tbl_name'`

3. **日志管理建议**：
   ```bash
   # 自动清理30天前日志
   find /var/lib/mysql -name "mysql-bin.*" -mtime +30 -exec rm {} \;
   ```

> **重要注意事项**  
> 1. 使用`REPAIR TABLE`前务必进行物理备份  
> 2. InnoDB表`OPTIMIZE`会重建表，建议在业务低峰期操作  
> 3. 二进制日志保留周期应大于全量备份周期