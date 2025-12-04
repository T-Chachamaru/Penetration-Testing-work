#### 概述：什么是 Wazuh？ (Overview: What is Wazuh?)

**Wazuh** 创建于 2015 年，是一款开源、免费且功能全面的 **EDR (Endpoint Detection and Response)** 解决方案。它采用**管理器-代理 (Manager-Agent)** 模型运行：一台或多台专门的设备作为管理器，负责分析和管理安装在受监控端点上的代理所发送的数据。

#### 1. Wazuh 代理 (The Wazuh Agent)

代理是安装在需要监控的设备（如服务器、工作站）上的轻量级程序。它负责实时监控系统事件和进程（如用户认证、文件变更、进程执行），并将收集到的日志发送给 Wazuh 管理器进行处理和分析。

##### 部署新代理 (Deploying a New Agent)

Wazuh 提供了一个直观的向导来简化代理的部署过程。

1. 在 Wazuh UI 中，导航至 `Wazuh -> Agents`。
    
2. 点击 `Deploy New Agent`。
    
3. 根据向导填写先决条件：
    
    - **操作系统 (Operating System)**: 选择代理将要安装的操作系统。
        
    - **Wazuh 服务器地址 (Wazuh server address)**: 输入管理器的 IP 地址或 DNS 名称。
        
    - **代理组 (Agent group)**: 选择代理将要加入的组。
        
4. 向导的第四步会生成一个完整的安装和配置命令，你只需将其复制并粘贴到目标端点上执行即可。
    

#### 2. 核心功能 (Core Capabilities)

##### 漏洞评估 (Vulnerability Assessment)

Wazuh 能够定期扫描代理，收集已安装的应用程序及其版本号，并将其与最新的 CVE 数据库进行比对，以主动发现潜在的安全漏洞。此模块在代理首次安装时会进行一次全面扫描，之后会按预设的时间间隔（默认为 5 分钟）运行。

##### 安全事件监控 (Security Event Monitoring)

Wazuh 根据其庞大的规则集来分析代理发送的日志，并对可疑活动（如文件删除、登录失败、恶意软件特征等）生成安全事件告警。

##### 策略审计 (Policy Auditing)

Wazuh 能够审计代理的系统配置，并根据多种合规性框架和标准（如 NIST, MITRE ATT&CK, GDPR）给出指标，帮助组织检查其安全策略的合规性。

#### 3. 告警分析：监控登录示例 (Alert Analysis: Monitoring Logins Example)

Wazuh 能够主动记录成功和失败的用户认证尝试。以下是一个检测到 SSH 登录失败（规则 ID `5710`）的告警示例。

|字段|值|描述|
|---|---|---|
|`agent.ip`|`10.10.73.118`|触发告警的代理的 IP 地址。|
|`agent.name`|`ip-10-10-73-118`|触发告警的代理的主机名。|
|`rule.description`|`sshd: Attempt to login using a non-existent user`|对告警事件的简要描述。|
|`rule.mitre.technique`|`Brute-Force`|告警关联的 MITRE ATT&CK 技术。|
|`rule.mitre.id`|`T1110`|告警关联的 MITRE ATT&CK 技术 ID。|
|`rule.id`|`5710`|Wazuh 规则集中为该告警分配的 ID。|
|`location`|`/var/log/auth.log`|代理上生成此告警的源日志文件位置。|

> **注意**: 所有告警都存储在 Wazuh 管理服务器上的 `/var/ossec/logs/alerts/alerts.log` 文件中。

#### 4. 日志收集 (Log Collection)

##### 收集 Windows 日志 (Sysmon)

Wazuh 可以与 **Sysmon** 完美集成，以收集更详细的 Windows 端点活动。

1. **配置 Sysmon**: 在 Windows 端点上，使用一个 XML 配置文件来启动 Sysmon，以定义需要监控的事件。
    
    Code snippet
    
    ```
    Sysmon64.exe -accepteula -i detect_powershell.xml
    ```
    
2. **配置 Wazuh 代理**: 编辑代理的配置文件 `C:\Program Files (x86)\ossec-agent\ossec.conf`，添加以下代码块以收集 Sysmon 事件日志。
    
    XML
    
    ```
    <localfile>
        <location>Microsoft-Windows-Sysmon/Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>
    ```
    
3. **配置 Wazuh 管理器**: 在管理器的 `/var/ossec/etc/rules/local_rules.xml` 文件中添加自定义规则，以便解析和告警特定的 Sysmon 事件。
    
    XML
    
    ```
    <group name="sysmon,">
        <rule id="255000" level="12">
            <if_group>sysmon_event1</if_group>
            <field name="sysmon.image">\\powershell.exe||\\.ps1</field>
            <description>Sysmon - Event 1: Bad exe: $(sysmon.image)</description>
        </rule>
    </group>
    ```
    

##### 收集 Linux 日志 (Apache)

Wazuh 内置了对多种 Linux 服务的日志分析规则（如 Docker, FTP, WordPress 等）。

1. **配置 Wazuh 代理**: 编辑代理的配置文件 `/var/ossec/etc/ossec.conf`，添加以下代码块来监控指定的日志文件（例如 Apache 日志）。
    
    XML
    
    ```
    <localfile>
        <location>/var/log/apache2/access.log</location>
        <log_format>apache</log_format>
    </localfile>
    ```
    

##### 审计 Linux 命令 (Auditd)

Wazuh 可以利用 `auditd` 服务来监控 Linux 系统上的命令执行。

1. **安装并配置 Auditd**: 在 Linux 代理上安装 `auditd`，并在 `/etc/audit/rules.d/audit.rules` 文件中添加规则，例如监控以 root 身份执行的所有命令。
    
    ```
    -a exit,always -F arch=b64 -F euid=0 -S execve -k audit-wazuh-c
    ```
    
2. **配置 Wazuh 代理**: 编辑代理的配置文件 `/var/ossec/etc/ossec.conf`，添加以下代码块以收集 `auditd` 的日志。
    
    XML
    
    ```
    <localfile>
        <location>/var/log/audit/audit.log</location>
        <log_format>audit</log_format>
    </localfile>
    ```
    

#### 5. 高级交互：API 与报告 (Advanced Interaction: API and Reporting)

##### 使用 Wazuh API

Wazuh 提供了丰富的 RESTful API，允许通过命令行与管理器进行交互。

1. **获取认证令牌**:
    
    Bash
    
    ```
    TOKEN=$(curl -u <user>:<pass> -k -X GET "https://<WAZUH_MANAGER_IP>:55000/security/user/authenticate?raw=true")
    ```
    
2. **使用令牌进行查询**:
    
    Bash
    
    ```
    # 检查管理器状态
    curl -k -X GET "https://<WAZUH_MANAGER_IP>:55000/manager/status?pretty=true" -H "Authorization: Bearer $TOKEN"
    
    # 列出活动代理
    curl -k -X GET "https://<WAZUH_MANAGER_IP>:55000/agents?pretty=true&status=active" -H "Authorization: Bearer $TOKEN"
    ```
    

##### 使用 API 控制台

Wazuh UI 内置了一个强大的 API 控制台 (`Wazuh -> Tools -> API Console`)，可以在 Web 界面中直接编写和运行 API 查询，非常方便。

##### 生成报告 (Generating Reports)

1. **选择视图**: 在 Wazuh UI 中，导航到你想要生成报告的模块（例如 `Modules -> Security events`）。
    
2. **生成报告**: 在视图的右上角，点击报告图标来生成基于当前视图和时间范围的报告。
    
3. **下载报告**: 导航至 `Wazuh -> Management -> Status and reports -> Reports`，在这里你可以看到所有已生成的报告列表，并可以将其下载为 PDF 文件。