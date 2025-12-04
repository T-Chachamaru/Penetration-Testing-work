#### 概述 (Overview)

**Kroll 证据解析和提取工具 (Kroll Artifact Parser and Extractor, KAPE)** 是一款功能强大的 Windows 取证证据解析与提取工具。它通过在完整的磁盘镜像过程完成之前，从实时系统或存储设备中快速提取关键证据，从而显著缩短事件响应时间。

KAPE 的设计有两个核心目的：

1. **收集文件 (Collect files)**: 根据预设的定义，精确查找并复制取证证据文件。
    
2. **处理文件 (Process collected files)**: 对收集到的文件运行指定的程序，以解析和提取信息。
    

为了实现这两个目的，KAPE 引入了 **目标 (Targets)** 和 **模块 (Modules)** 的概念。

- **目标 (Targets)**: 定义了需要收集的取证证据（例如，Prefetch 文件、注册表 Hive）。
    
- **模块 (Modules)**: 定义了用于处理已收集证据并从中提取信息的程序（例如，运行 Prefetch 解析器）。
    

#### KAPE 工作原理与目录结构 (How KAPE Works & Directory Structure)

KAPE 的工作流程高度可配置且可扩展。其核心是 `kape.exe` 二进制文件，根据用户提供的配置来收集和处理文件。

##### 文件收集流程 (File Collection Process)

KAPE 的文件收集过程采用**双通道复制机制**，以确保最大限度地获取文件：

1. **第一次通过**: 复制所有未被操作系统锁定的文件，并将它们加入队列。
    
2. **第二次通过**: 对于第一次未能复制的锁定文件（如活动的注册表 Hive），KAPE 使用原始磁盘读取技术绕过操作系统锁来完成复制。
    

所有复制的文件都会保留其原始的时间戳和元数据，并以与源系统相似的目录结构存储在目标位置。

##### 目录结构

在 KAPE 的主目录中，可以看到以下关键文件和目录：

- `kape.exe`: KAPE 的命令行版本。
    
- `gkape.exe`: KAPE 的图形用户界面（GUI）版本。
    
- `gkape.settings`: 存储 GUI 版本的默认设置。
    
- `Get-KAPEUpdate.ps1`: 一个用于检查和下载 KAPE 更新的 PowerShell 脚本。
    
- `Targets/`: 存放所有“目标”定义文件的目录。
    
- `Modules/`: 存放所有“模块”定义文件的目录。
    
- `bin/`: 存放模块运行时所需的可执行文件（如 Eric Zimmerman 的工具集）。
    

#### KAPE 核心概念 (Core Concepts of KAPE)

##### 1. 目标 (Targets)

在 KAPE 中，“目标”指的是需要从源系统（活动主机或磁盘镜像）中收集并复制到指定目的地的证据文件。简单来说，Targets 的任务是**将文件从一个地方复制到另一个地方**。

- **定义文件**: 目标由 `.tkape` 扩展名的文件定义，这些文件包含了要收集的证据的路径、类别和文件掩码等信息。
    
- **复合目标 (Compound Targets)**: 为了提高效率，KAPE 支持复合目标。这些是包含多个单一目标的集合，允许通过一个命令收集多种类型的证据。
    
    - **示例**: `!BasicCollection`, `!SANS_triage`, `KAPEtriage`。
        
    - **位置**: `KAPE\Targets\Compound\`
        
- **特殊目录**:
    
    - **`!Disabled`**: 存放暂时不想在活动目标列表中显示的 Targets。
        
    - **`!Local`**: 存放用户自定义且不希望与 KAPE 的 Github 仓库同步的 Targets。更新 KAPE 时，不在官方仓库中的自定义文件也会被移动到此目录。
        

##### 2. 模块 (Modules)

“模块”负责对收集到的文件集运行特定的工具或命令，其目标是**处理数据并存储输出**，而不是简单地复制文件。输出结果通常是 CSV 或 TXT 格式的报告。

- **定义文件**: 模块由 `.mkape` 扩展名的文件定义。这些文件指定了需要运行哪个可执行文件、其命令行参数以及输出的格式和文件名。
    
- **bin 目录**: 由于模块需要运行的许多取证工具（如 Eric Zimmerman 的工具）并非 Windows 系统原生自带，这些工具的可执行文件需要存放在 `bin/` 目录中。KAPE 会自动从该目录或指定的完整路径中调用它们。
    
- **复合模块 (Compound Modules)**: 与复合目标类似，复合模块允许一次性运行多个处理模块，例如 `!EZParser` 会运行 Eric Zimmerman 工具集中的多个解析器。
    
- **特殊目录**: `!Disabled` 和 `!Local` 目录的功能与 Targets 中的同名目录相同。
    

#### KAPE 使用方法 (Using KAPE)

##### 1. KAPE 图形界面 (gkape.exe)

对于偏好图形化操作的用户，`gkape.exe` 提供了直观的界面。

**目标选项 (Target Options - 窗口左侧)**

- 启用 **Use Target Options** 复选框以激活。
    
- **Target Source**: 选择证据来源，例如 `C:\` 代表当前运行的系统。
    
- **Target Destination**: 设置收集到的证据的存储位置。
    
- **Flush**: 选中此项会在执行前清空目标目录。**请谨慎使用**。
    
- **Add %d / Add %m**: 分别将日期和机器名信息附加到目标目录名称中，便于整理。
    
- **Process VSCs**: 可选择是否处理卷影副本 (Volume Shadow Copies)。
    
- **Transfer**: 支持将收集到的证据通过 SFTP 或 S3 传输，并可封装为 Zip, VHD, 或 VHDX 容器。
    

**模块选项 (Module Options - 窗口右侧)**

- 启用 **Use Module Options** 复选框以激活。
    
- **Module Destination**: 设置模块处理后输出报告的存储位置。
    
- 当同时使用目标和模块时，KAPE 会自动将**目标输出目录 (Target Destination)作为模块的输入源 (Module Source)**。
    

**执行**

1. 选择一个或多个目标（例如，复合目标 `KapeTriage`）。
    
2. 选择一个或多个模块（例如，复合模块 `!EZParser`）。
    
3. **Current command line** 区域会实时显示根据当前 GUI 设置生成的等效命令行。
    
4. 点击右下角的 **Execute!** 按钮开始执行。一个命令行窗口会弹出并显示实时日志。
    

##### 2. KAPE 命令行界面 (kape.exe CLI)

对于自动化和脚本编写，命令行是更高效的选择。在 PowerShell 或 CMD 中以**管理员身份**运行 `kape.exe`。

**常用参数**:

- `--tsource`: 指定目标源路径。
    
- `--target`: 指定要使用的目标名称。
    
- `--tdest`: 指定目标输出路径。
    
- `--tflush`: 清空目标输出目录（等同于 GUI 的 Flush）。
    
- `--module`: 指定要使用的模块名称。
    
- `--mdest`: 指定模块输出路径。
    
- `--msource`: 指定模块输入路径（如果省略，则默认使用 `--tdest` 的路径）。
    

**命令示例 (收集并处理)**

以下命令演示了如何使用 `KapeTriage` 复合目标收集证据，并用 `!EZParser` 复合模块进行处理：

PowerShell

```
# 1. 指定源、目标和目标输出路径
kape.exe --tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\Target

# 2. 在上述基础上，添加模块和模块输出路径
# KAPE 会自动将 --tdest 的路径作为模块的输入源
kape.exe --tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\Target --mdest C:\Users\thm-4n6\Desktop\module --module !EZParser
```

**注意**: 运行此命令需要管理员权限，以确保 KAPE 能够访问所有系统文件。

##### 3. 批量模式 (Batch Mode)

KAPE 支持通过一个名为 `_kape.cli` 的文件进行批量处理。

1. 创建一个名为 `_kape.cli` 的文本文件。
    
2. 将所有需要执行的命令行参数写入该文件（无需 `kape.exe` 本身）。
    
    ```
    --tsource C: --target KapeTriage --tdest C:\Users\thm-4n6\Desktop\Target --mdest C:\Users\thm-4n6\Desktop\module --module !EZParser
    ```
    
3. 将 `_kape.cli` 文件与 `kape.exe` 放在同一个目录下。
    
4. 以**管理员身份**直接运行 `kape.exe`。它会自动检测并执行 `_kape.cli` 文件中的命令。这种方式非常适合让非专业人员在现场快速执行标准的证据收集流程。