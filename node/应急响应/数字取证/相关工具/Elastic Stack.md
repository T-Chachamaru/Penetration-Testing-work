#### 概述：什么是 Elastic Stack？ (Overview: What is the Elastic Stack?)

**Elastic Stack** (有时也称为 ELK Stack) 是由多个开源组件构成的强大组合，它们协同工作，帮助用户从任何来源、以任何格式提取数据，并对其进行实时的搜索、分析和可视化。

##### 核心组件 (Core Components)

- **Elasticsearch**:
    
    - **功能**: 一个基于 JSON 的全文搜索和分析引擎。它是整个堆栈的核心，负责存储、索引、分析和关联数据。
        
    - **交互**: 支持通过 RESTful API 与数据进行交互。
        
- **Logstash**:
    
    - **功能**: 一个灵活的数据处理引擎，用于从各种来源提取数据，对其进行转换和规范化，然后发送到指定的目标。
        
    - **配置文件结构**: 分为三个部分：
        
        1. **输入 (Input)**: 定义数据来源，支持众多[输入插件](https://www.elastic.co/guide/en/logstash/8.1/input-plugins.html)。
            
        2. **过滤器 (Filter)**: 对输入的数据进行解析、转换或丰富，支持众多[过滤器插件](https://www.elastic.co/guide/en/logstash/8.1/filter-plugins.html)。
            
        3. **输出 (Output)**: 定义处理后的数据的发送目的地，如 Elasticsearch、文件等，支持众多[输出插件](https://www.elastic.co/guide/en/logstash/8.1/output-plugins.html)。
            
- **Beats**:
    
    - **功能**: 一系列轻量级的、单一用途的数据传输代理，安装在终端主机上，用于采集不同类型的数据并将其发送到 Logstash 或 Elasticsearch。
        
    - **示例**: `Winlogbeat` 用于采集 Windows 事件日志，`Packetbeat` 用于采集网络流量。
        
- **Kibana**:
    
    - **功能**: 一个基于 Web 的数据可视化工具。它与 Elasticsearch 紧密集成，用于实时分析、查询和展示数据。用户可以通过 Kibana 创建各种图表、地图和仪表板。
        

##### 它们如何协同工作 (How They Work Together)

1. **Beats** 在终端上收集数据（如日志、指标、网络包）。
    
2. 数据被发送到 **Logstash**，在这里进行解析、过滤和丰富，将其转换为结构化的 JSON 格式。
    
3. 处理后的数据被发送并存储在 **Elasticsearch** 中，等待被索引和查询。
    
4. **Kibana** 连接到 Elasticsearch，允许用户通过友好的 Web 界面搜索、分析和可视化这些数据。
    

#### 使用 Kibana 进行分析 (Analysis with Kibana)

##### “发现” (Discover) 标签页：核心分析界面

“发现” (Discover) 标签页是分析师在 Kibana 中花费时间最多的地方，也是进行日志调查的核心界面。

**主要界面元素**:

- **日志 (文档)**: 中央区域显示了每个日志事件的详细信息，每个日志被称为一个“文档”。
    
- **字段面板 (Field Panel)**: 左侧面板列出了从日志中解析出的所有字段。
    
- **索引模式 (Index Pattern)**: 左上角允许用户选择要查询的数据集（索引）。
    
- **搜索栏 (Search Bar)**: 顶部用于输入查询语句 (KQL) 和应用过滤器。
    
- **时间过滤器 (Time Filter)**: 右上角用于根据时间范围筛选日志。
    
- **时间轴 (Timeline)**: 搜索栏下方是一个条形图，显示了在选定时间范围内事件数量的分布。
    

#### Kibana 关键功能详解 (Key Kibana Features in Detail)

##### 时间过滤器 (Time Filter)

它允许分析师根据预设的时间范围（如过去 15 分钟、过去 7 天）或自定义的绝对时间范围来筛选日志。**快速选择 (Quick select)** 菜单还包含一个**自动刷新 (auto-refresh)** 选项，可以设置 Kibana 每隔几秒（例如 5 秒）自动刷新并显示最新的日志。

##### 时间轴面板 (Timeline Panel)

位于搜索栏下方的条形图直观地展示了事件数量随时间的变化。这个图表对于快速**识别异常峰值**（例如，在某个时间点日志量突然激增）非常有用，这些峰值往往是调查的切入点。

##### 索引模式 (Index Patterns)

索引模式是 Kibana 用于访问 Elasticsearch 数据的“地图”。它定义了 Kibana 应该查询哪些索引，以及这些索引中包含哪些字段及其数据类型。由于不同的日志源（如防火墙日志、Windows 事件日志）结构不同，为每个数据源创建专门的索引模式是实现数据规范化和有效查询的基础。

##### 字段面板 (Field Panel)

左侧的字段面板列出了当前索引模式中所有可用的字段。

- 点击任何一个字段，它会显示该字段**最常见的前 5 个值**及其出现频率。
    
- 每个值旁边都有 `+` (放大镜) 和 `-` (放大镜) 按钮，点击它们可以快速创建**包含此值 (must)** 或**排除此值 (must not)** 的过滤器。
    

##### 创建自定义表格视图 (Creating Custom Table Views)

默认情况下，日志以原始 JSON 格式显示。为了减少混乱，你可以从左侧字段面板中选择你感兴趣的字段，将它们添加到主显示区域。这会创建一个整洁的**表格视图**，只显示对你重要的列，使分析更具表现力和意义。

#### KQL：Kibana 查询语言 (KQL: The Kibana Query Language)

**KQL (Kibana Query Language)** 是一种简单直观的查询语言，用于在 Kibana 的搜索栏中筛选 Elasticsearch 的数据。

##### 自由文本搜索 (Free-text Search)

直接输入一个词条（如 `security`），KQL 将返回所有字段中包含该词条的文档。

```
security
```

##### 通配符搜索 (Wildcard Search)

使用星号 `*` 作为通配符来匹配词条的一部分。

```
sec*
```

##### 逻辑运算符 (Logical Operators)

使用 `AND`, `OR`, `NOT` 来组合多个查询条件。

```
(error OR failure) AND security
```

##### 基于字段的搜索 (Field-based Search)

这是最精确的搜索方式，语法为 `FIELD : VALUE`。

- **示例**: 查找源 IP 地址为 `192.168.1.10` 的所有日志。
    
    ```
    source.ip : "192.168.1.10"
    ```
    
- **示例**: 查找所有事件 ID 为 `4624` 的 Windows 登录成功事件。
    
    ```
    winlog.event_id : 4624
    ```