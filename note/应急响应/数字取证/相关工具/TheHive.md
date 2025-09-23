#### 概述：什么是 TheHive？ (Overview: What is TheHive?)

**TheHive 项目**是一个可扩展、开源且免费的安全事件响应平台 (SIRP)。它旨在协助在安全运营中心 (SOC)、计算机安全应急响应小组 (CSIRT) 和计算机应急响应小组 (CERT) 工作的安全分析师，以快速、协作的方式追踪、调查和应对安全事件。

分析师可以同时协作进行调查，通过平台的直播流功能，确保所有团队成员都能实时获取有关案件、任务、可观察项和 IOCs 的最新信息。

##### 三大核心功能 (Three Core Functions)

1. **协作 (Collaboration)**: 允许多名分析师同时处理同一个案件。通过其实时直播功能，团队中的每个人都可以实时关注案件的进展。
    
2. **详细说明 (Elaboration)**: 每个调查都对应一个案件。案件可以分解为具体的任务，这些任务可以手动创建或通过模板引擎生成。分析师可以记录进展、附加证据并轻松分配任务。
    
3. **行动 (Action)**: 支持快速的分诊流程，允许分析师向案件中添加**可观察项 (Observables)**，使用标签将其标记为**攻击指标 (IOCs)**，并利用平台的威胁情报能力识别历史数据中出现过的可观察项。
    

#### TheHive 功能与集成 (TheHive Features & Integrations)

TheHive 平台通过丰富的功能集和强大的集成能力，支持并优化了分析师的工作流程。

- **案件/任务管理 (Case/Task Management)**: 每次调查都对应一个案件，每个案件可以分解为一个或多个任务。分析师可以记录进展、附加证据，并使用模板来标准化响应流程。
    
- **警报筛选 (Alert Triage)**: 支持从 SIEM、电子邮件报告或其他安全事件源导入警报。分析师可以在平台内对警报进行筛选，并决定是否将其升级为正式的调查案件。
    
- **使用 Cortex 进行可观察项丰富 (Observable Enrichment with Cortex)**: **Cortex** 是一个可观察项分析和主动响应引擎，也是 TheHive 最核心的集成之一。它允许分析师对案件中的可观察项（如 IP 地址、域名、文件哈希）运行分析器 (Analyzers)，从而自动丰富信息、进行关联分析并发现攻击模式。
    
- **主动响应 (Active Response)**: 分析师可以使用响应器 (Responders) 来执行主动操作，例如阻止 IP、隔离主机或将事件信息分享到其他系统。
    
- **定制仪表盘 (Custom Dashboards)**: 平台可以汇总案件、任务、可观察项等统计数据，并在可定制的仪表板中展示，用于生成有价值的 KPI 报告。
    
- **内置 MISP 集成 (Built-in MISP Integration)**: **MISP** 是一个用于共享和关联威胁情报的平台。TheHive 与其集成后，分析师可以从 MISP 事件中创建案件，导入 IOCs，或将自己发现的指标导出到 MISP 社区。
    
- **其他集成**: TheHive 还支持 DigitalShadows2TH、ZeroFox2TH 等警报源扩展，确保外部警报可以无缝流入平台并进行处理。
    

#### 用户配置文件与权限 (User Profiles & Permissions)

TheHive 允许管理员根据预设的用户配置文件为组织内的分析师分配不同角色。

##### 预设用户配置文件 (Pre-set User Profiles)

- `admin`: 拥有平台的完全管理权限（如管理组织、配置），但不能直接处理案件。
    
- `org-admin`: 组织的管理员，可以管理用户和组织级别的配置，并拥有处理案件、任务和运行分析器的全部权限。
    
- `analyst`: 核心分析师角色，可以创建和编辑案件、任务、可观察项，并运行分析器和响应器。
    
- `read-only`: 只能查看案件、任务和可观察项的详细信息，无法进行任何修改。
    

##### 详细权限列表 (Detailed Permissions List)

|权限|Functions|功能|
|---|---|---|
|`manageOrganisation` (1)|Create & Update an organisation|创建和更新组织|
|`manageConfig` (1)|Update Configuration|更新配置|
|`manageProfile` (1)|Create, update & delete Profiles|创建、更新和删除配置文件|
|`manageTag` (1)|Create, update & Delete Tags|创建、更新和删除标签|
|`manageCustomField` (1)|Create, update & delete Custom Fields|创建、更新和删除自定义字段|
|`manageCase`|Create, update & delete Cases|创建、更新和删除案例|
|`manageObservable`|Create, update & delete Observables|创建、更新和删除可观察项|
|`manageAlert`|Create, update & import Alerts|创建、更新和导入警报|
|`manageUser`|Create, update & delete Users|创建、更新和删除用户|
|`manageCaseTemplate`|Create, update & delete Case templates|创建、更新和删除案例模板|
|`manageTask`|Create, update & delete Tasks|创建、更新和删除任务|
|`manageShare`|Share case, task & observable|与其他组织共享案例、任务和可观察对象|
|`manageAnalyse` (2)|Execute Analyse|执行分析|
|`manageAction` (2)|Execute Actions|执行操作 (响应器)|
|`manageAnalyserTemplate` (2)|Create, update & delete Analyser Templates|创建、更新和删除分析器模板|

> 注意:
> 
> (1) 组织、配置、配置文件和标签是全局对象，相关权限仅在“admin”组织上生效。
> 
> (2) 只有在启用 Cortex 连接器的情况下，才能使用分析、操作和分析器模板相关的权限。

#### 分析师界面导航 (Analyst Interface Navigation)

分析师登录后，顶部菜单提供了创建新案件、查看任务和警报等选项。主控制台会显示当前组织内的活动案件列表。

##### 创建新案件 (Creating a New Case)

点击 **New Case** 后，会弹出一个窗口，要求填写案件详情。以下分类字段对于案件管理和信息共享至关重要：

- **严重性 (Severity)**: 事件对环境的影响程度，分为低 (Low)、中 (Medium)、高 (High)、关键 (Critical)。
    
- **TLP (Traffic Light Protocol)**: 一套信息共享协议，用于确保敏感信息只与适当的受众共享。
    
    - `WHITE` (完全公开) -> `GREEN` -> `AMBER` -> `RED` (严格限制)。更多信息可参考 [CISA 网站](https://www.cisa.gov/tlp)。
        
- **PAP (Permissible Actions Protocol)**: 用于指示分析师可以如何使用案件信息，以及攻击者是否能感知到当前的分析活动。它同样使用颜色方案，是 MISP 分类法的一部分。
    

##### 映射到 MITRE ATT&CK (Mapping to MITRE ATT&CK)

在创建或调查案件时，分析师可以将案件与 MITRE ATT&CK 框架中的特定战术、技术和过程 (TTPs) 相关联。这为绘制威胁图谱和理解攻击者行为提供了宝贵的上下文。

- **示例**: 在一个数据泄露调查中，如果发现攻击者通过非 C2 协议泄露未加密数据，可以将其映射到 **T1048.003: Exfiltration Over Unencrypted Non-C2 Protocol**。