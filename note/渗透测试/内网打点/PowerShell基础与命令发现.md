### 1. 概述
PowerShell是Windows下的强大命令行Shell和脚本语言，用于系统管理和自动化。了解如何查找和使用命令是基础。
#### 方法/工具
1.  **更改目录**
    *   `Set-Location -Path <路径>`: 更改当前工作目录。
    *   别名: `cd`, `sl`
    *   示例: `Set-Location -Path "C:\Users\Public\Documents"`
2.  **命令发现**
    *   `Get-Command`: 获取当前会话中所有可用的命令（Cmdlet、函数、别名、应用程序）。
    *   `Get-Command -CommandType <类型>`: 根据类型筛选命令 (e.g., `Function`, `Cmdlet`, `Alias`)。
    *   示例: `Get-Command -CommandType Function`
3.  **命令帮助**
    *   `Get-Help <命令名>`: 获取指定命令的详细帮助信息。
    *   `Get-Help <命令名> -Examples`: 显示命令的使用示例。
    *   别名: `help`, `man`
    *   示例: `Get-Help Get-Process -Examples`
4.  **命令别名**
    *   `Get-Alias`: 列出所有已定义的命令别名及其对应的命令。
5.  **模块管理 (在线)**
    *   `Find-Module -Name "<模块名模式>"`: 在PowerShell Gallery等在线存储库中搜索模块。
    *   `Install-Module -Name "<模块名>"`: 从在线存储库下载并安装模块。
    *   示例: `Find-Module -Name "*Azure*"`
    *   示例: `Install-Module -Name "PowerShellGet" -Force` (安装或更新核心模块)

### 2. 文件与目录操作
#### 概述
使用PowerShell进行常见的文件系统管理任务，如列表、创建、删除、复制和移动文件/目录。
#### 方法/工具
1.  **列出文件和目录**
    *   `Get-ChildItem -Path <路径>`: 列出指定路径下的文件和目录。
    *   别名: `gci`, `dir`, `ls`
    *   示例: `Get-ChildItem -Path C:\Windows`
2.  **创建文件或目录**
    *   `New-Item -Path <完整路径> -ItemType <类型>`: 创建新项。类型可以是 `File` 或 `Directory`。
    *   别名: `ni`
    *   示例 (文件): `New-Item -Path ".\newfile.txt" -ItemType File`
    *   示例 (目录): `New-Item -Path ".\newdir" -ItemType Directory`
3.  **删除文件或目录**
    *   `Remove-Item -Path <路径>`: 删除指定的文件或目录 (对目录使用 `-Recurse` 删除非空目录)。
    *   别名: `ri`, `rm`, `del`, `rmdir`
    *   示例: `Remove-Item -Path ".\oldfile.txt"`
    *   示例: `Remove-Item -Path ".\olddir" -Recurse`
4.  **复制文件或目录**
    *   `Copy-Item -Path <源路径> -Destination <目标路径>`: 复制项 (对目录使用 `-Recurse`)。
    *   别名: `cpi`, `copy`, `cp`
    *   示例: `Copy-Item -Path .\myfile.txt -Destination C:\backup\`
5.  **移动或重命名文件或目录**
    *   `Move-Item -Path <源路径> -Destination <目标路径>`: 移动或重命名项。
    *   别名: `mi`, `move`, `mv`
    *   示例 (移动): `Move-Item -Path .\myfile.txt -Destination C:\temp\`
    *   示例 (重命名): `Move-Item -Path .\oldname.txt -Destination .\newname.txt`
6.  **读取文件内容**
    *   `Get-Content -Path <文件路径>`: 读取文件内容。
    *   别名: `gc`, `type`, `cat`
    *   示例: `Get-Content -Path ".\config.log"`

### 3. 管道与数据处理
#### 概述
PowerShell的核心特性之一是管道 (`|`)，它允许将一个命令的输出对象传递给另一个命令作为输入，实现强大的数据流处理。
#### 方法/工具
1.  **排序 (`Sort-Object`)**
    *   根据对象的属性对通过管道传递的数据进行排序。
    *   别名: `sort`
    *   示例: `Get-ChildItem | Sort-Object Length -Descending` (按文件大小降序排序)
2.  **筛选 (`Where-Object`)**
    *   根据指定的条件筛选通过管道传递的对象。
    *   别名: `where`, `?`
    *   常用比较运算符: `-eq` (等于), `-ne` (不等于), `-gt` (大于), `-ge` (大于等于), `-lt` (小于), `-le` (小于等于), `-like` (通配符匹配), `-match` (正则匹配), `-contains` (包含), `-notcontains` (不包含)
    *   示例: `Get-Process | Where-Object -Property CPU -gt 100` (查找CPU使用率高的进程)
    *   示例: `Get-ChildItem | Where-Object -Property Extension -eq ".log"` (查找.log文件)
3.  **选择属性 (`Select-Object`)**
    *   从通过管道传递的对象中选择指定的属性（列）。
    *   别名: `select`
    *   参数: `-Property <属性列表>`, `-First <数量>`, `-Last <数量>`, `-Unique`, `-ExpandProperty <属性名>`
    *   示例: `Get-Process | Select-Object Name, Id, CPU` (只显示进程名、ID和CPU使用)
    *   示例: `Get-ChildItem | Select-Object -First 5` (显示前5个文件/目录)
4.  **文本搜索 (`Select-String`)**
    *   在文件内容或字符串输入中搜索匹配指定模式（支持正则表达式）的文本行。
    *   别名: `sls` (类似Linux的`grep`或Windows的`findstr`)
    *   参数: `-Path <路径>`, `-Pattern <搜索模式>`, `-CaseSensitive`, `-SimpleMatch` (禁用正则)
    *   示例 (文件搜索): `Select-String -Path ".\*.log" -Pattern "Error"` (在所有.log文件中搜索"Error")
    *   示例 (管道搜索): `Get-Content .\myfile.txt | Select-String -Pattern "password"`

### 4. 系统信息查询
#### 概述
获取有关本地计算机硬件、操作系统、用户和网络配置的信息。
#### 方法/工具
1.  **综合系统信息**
    *   `Get-ComputerInfo`: 检索全面的系统和操作系统信息。
    *   (类似 `systeminfo.exe`)
2.  **本地用户账户**
    *   `Get-LocalUser`: 列出系统上的所有本地用户账户。
3.  **网络配置**
    *   `Get-NetIPConfiguration`: 提供网络接口的详细配置信息 (IP地址、子网掩码、网关、DNS)。
    *   (类似 `ipconfig /all`)
4.  **IP地址信息**
    *   `Get-NetIPAddress`: 仅提供IP地址相关的详细信息。

### 5. 进程、服务与网络状态
#### 概述
查看当前运行的进程、系统服务状态以及网络连接情况。
#### 方法/工具
1.  **进程查看**
    *   `Get-Process`: 提供所有当前正在运行的进程的详细视图。
    *   别名: `gps`, `ps`
2.  **服务查看**
    *   `Get-Service`: 提供当前计算机上所有服务的状态信息。
3.  **TCP连接查看**
    *   `Get-NetTCPConnection`: 显示当前的TCP连接及其状态（监听端口、活动连接等）。
    *   (类似 `netstat -ano`)

### 6. 文件哈希计算
#### 概述
计算文件的哈希值，常用于验证文件完整性或识别文件。
#### 方法/工具
1.  **计算文件哈希**
    *   `Get-FileHash -Path <文件路径>`: 计算指定文件的哈希值。
    *   默认算法: SHA256。可以使用 `-Algorithm` 参数指定其他算法 (e.g., `MD5`, `SHA1`, `SHA384`, `SHA512`)。
    *   示例: `Get-FileHash -Path .\important.zip -Algorithm MD5`

### 7. 远程命令执行
#### 概述
使用PowerShell Remoting (基于WinRM协议) 在远程计算机上执行命令或脚本。需要远程计算机启用并配置WinRM。
#### 方法/工具
1.  **调用命令 (`Invoke-Command`)**
    *   `Invoke-Command -ComputerName <远程计算机名或IP> -ScriptBlock { <要执行的命令> }`: 在单台或多台远程计算机上执行脚本块。
    *   `Invoke-Command -ComputerName <远程计算机名> -FilePath <本地脚本路径>`: 将本地脚本文件发送到远程计算机并执行。
    *   `-Credential <凭据对象或用户名>`: 使用指定凭据进行身份验证。
    *   示例 (脚本块): `Invoke-Command -ComputerName Server01, Server02 -ScriptBlock { Get-Process winlogon }`
    *   示例 (凭据): `Invoke-Command -ComputerName Server01 -Credential Domain01\User01 -ScriptBlock { Get-Culture }`
    *   示例 (脚本文件): `Invoke-Command -ComputerName WebServer01 -FilePath C:\Scripts\DeployApp.ps1`