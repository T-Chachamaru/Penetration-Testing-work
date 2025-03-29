## SQL注入

### 1. 数字型注入
- **前端形式**：基于 POST 的 `select` 表单。
- **步骤**：
  1. 使用 Burp Suite 抓取请求包，并发送至 Repeater 模块。
     - 示例请求包：![SQL 1](/pikachu/images/sql1.jpeg)
  2. 构造 `or 1=1`，注入成功，返回所有数据。
     - 结果：![SQL 2](/pikachu/images/sql2.png)
  3. 猜测 `SELECT` 查询返回两列，构造 `id=1 union select 1,group_concat(schema_name) from information_schema.schemata`，注入成功，确认数据库权限畅通。
     - 结果：![SQL 3](/pikachu/images/sql3.png)
- **结论**：数字型注入无需闭合，直接附加条件即可。

### 2. 字符型注入
- **前端形式**：基于 GET 的 `input-text` 表单。
  - 示例界面：![SQL 4](/pikachu/images/sql5.png)
- **步骤**：
  1. 输入单引号 `'`，构造闭合，触发报错，确认闭合符号为单引号。
     - 报错结果：![SQL 5](/pikachu/images/sql6.png)
  2. 构造 `' or 1=1 #`，注入成功，返回所有数据。
     - 结果：![SQL 6](/pikachu/images/sql7.png)
- **结论**：需闭合单引号，使用 `#` 注释后续语句。

### 3. 搜索型注入
- **前端形式**：基于 GET 的 `input-text` 表单。
  - 示例界面：![SQL 7](/pikachu/images/sql8.png)
- **步骤**：
  1. 输入任意字符搜索，观察结果，推测后端使用 `LIKE '%val%'` 通配符。
     - 搜索结果：![SQL 8](/pikachu/images/sql9.png)
  2. 输入 `%'`，构造闭合，触发报错，确认通配符为 `%` 且闭合为单引号。
     - 报错结果：![SQL 9](/pikachu/images/sql10.png)
  3. 构造 `%' or 1=1 #`，注入成功，返回所有数据。
     - 结果：![SQL 10](/pikachu/images/sql11.png)
- **结论**：搜索型注入需处理通配符和单引号闭合。

### 4. XX 型注入
- **前端形式**：基于 GET 的 `input-text` 表单。
  - 示例界面：![SQL 11](/pikachu/images/sql12.png)
- **步骤**：
  1. 输入 `'`，构造闭合，触发报错，确认闭合为单引号加小括号 `')`。
     - 报错结果：![SQL 12](/pikachu/images/sql13.png)
  2. 构造 `') or 1=1 #`，注入成功。
     - 结果：![SQL 13](/pikachu/images/sql14.png)
- **结论**：需闭合单引号和小括号，使用 `#` 注释。

### 5. INSERT/UPDATE 注入
- **前端形式**：任何提交或修改类型的表单。
- **步骤**：
  1. 使用 Burp Suite 抓取请求包，输入单引号 `'`，触发报错，确认 `username` 字段由单引号闭合。
     - 报错结果：![SQL 14](/pikachu/images/sql15.png)
  2. 构造 `123' or updatexml(1,concat(0x7e,database(),0x7e),1) or '`，注入成功，返回数据库名。
     - 结果：![SQL 15](/pikachu/images/sql16.png)
  3. `UPDATE` 注入形式类似。
- **结论**：利用报错注入提取信息，需闭合单引号。

### 6. DELETE 注入
- **前端形式**：留言板删除功能。
  - 示例界面：![SQL 16](/pikachu/images/sql17.png)
- **步骤**：
  1. 创建留言，拦截删除请求，获取传参。
     - 请求包：![SQL 17](/pikachu/images/sql18.png)
  2. 输入单引号 `'`，触发报错，确认参数为数值型。
  3. 构造 `56 or updatexml(1,concat(0x7e,database(),0x7e),1) #`，注入成功，返回数据库名。
     - 结果：![SQL 19](/pikachu/images/sql20.png)
- **结论**：数字型注入，无需闭合，直接附加报错 payload。

### 7. HTTP 头部注入
- **前端形式**：登录请求。
- **步骤**：
  1. 登录时抓包，发现请求头（如 Cookie）可注入。
     - 请求包：![SQL 20](/pikachu/images/sql21.png)
  2. 在 Cookie 中构造 `admin' or updatexml(1,concat(0x7e,version(),0x7e),1) #`，注入成功，返回版本信息。
     - 结果：![SQL 21](/pikachu/images/sql22.png)
- **结论**：头部注入需闭合单引号，适用于 Cookie 等字段。

### 8. 布尔盲注
- **前端形式**：输入框。
- **步骤**：
  1. 输入 `1' and 1=1 #`，确认注入点，返回正常结果。
     - 结果：![SQL 22](/pikachu/images/sql23.png)
  2. 使用 Burp Suite Intruder，构造 `1' and length(database())=val #`，爆破数据库名长度。
     - 爆破结果：![SQL 23](/pikachu/images/sql24.png)
- **结论**：基于布尔条件判断，需闭合单引号。

### 9. 时间盲注
- **方法**：
  - 使用布尔盲注格式，构造 `if(condition,sleep(x),0)`。
  - 示例：`1' and if(1=1,sleep(5),0) #`，通过响应时间判断条件真假。
  - 直接使用 SQLMap 自动化注入。
- **结论**：基于时间延迟，无需配图，推荐工具辅助。

### 10. 宽字节注入
- **前提**：
  - PHP 配置 `magic_quotes_gpc=ON`，会对 `'`、`"`、`\` 等字符转义为 `\`（URL 编码为 `%5c`）。
  - MySQL 使用 GBK 字符集，宽字节（如 `%df%5c`）可被解析为一个字符，绕过转义。
- **步骤**：
  1. 抓包，输入单引号 `'`，检测闭合。
  2. 使用 `order by` 确定字段数。
  3. 构造 `name=1%df' union select version(),database() #`，注入成功。
- **结论**：利用宽字节（如 `%df%5c`）绕过转义，闭合单引号。