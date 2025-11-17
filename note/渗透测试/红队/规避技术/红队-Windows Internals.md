
#### 目录
- [进程](#进程-processes)
- [线程](#线程-threads)
- [虚拟内存](#虚拟内存-virtual-memory)
- [动态链接库](#动态链接库-dynamic-link-libraries---dlls)
- [可移植可执行文件格式](#可移植可执行文件格式-portable-executable---pe-format)
- [与 Windows 内部交互](#与-windows-内部交互-interacting-with-windows-internals)

#### 进程 (Processes)

##### 1. 定义与重要性 (Definition and Importance)

一个**进程 (Process)** 代表了一个正在执行的程序实例。一个应用程序可能由一个或多个进程组成。进程是操作系统进行资源分配和调度的基本单位。微软文档对进程的描述包含以下要素：“每个进程提供了执行程序所需的资源。一个进程拥有一个虚拟地址空间、可执行代码、对系统对象的打开句柄、一个安全上下文、一个唯一的进程标识符、环境变量、一个优先级类别、最小和最大工作集大小，以及至少一个执行线程。”

进程是由应用程序的执行创建的，是 Windows 功能的核心。许多系统功能本身也作为进程运行，例如：

- **MsMpEng.exe**: Microsoft Defender Antivirus Service
- **wininit.exe**: Windows Start-Up Application (处理键盘、鼠标初始化等)
- **lsass.exe**: Local Security Authority Subsystem Service (负责凭据存储、用户登录等安全策略)

##### 2. 进程的关键组成部分 (Key Components of a Process)

进程包含多个组成部分，可以从较高层面归纳为以下关键特征：

|   |   |
|---|---|
|**组件 (Component)**|**描述 (Description)**|
|**私有虚拟地址空间 (Private Virtual Address Space)**|进程被分配的、隔离的虚拟内存地址范围。|
|**可执行程序 (Executable Program)**|定义了存储在虚拟地址空间中的代码和初始化数据。|
|**打开句柄列表 (List of Open Handles)**|定义了进程可以访问的系统资源（如文件、注册表键、其他进程等）的句柄。|
|**安全上下文 (Security Context)**|通常由访问令牌 (Access Token) 定义，包含了用户身份、所属安全组、持有的特权 (Privileges) 等安全相关信息。|
|**唯一进程ID (Unique Process ID - PID)**|操作系统为每个进程分配的唯一数字标识符。|
|**线程 (Threads)**|进程中实际执行代码的单元，一个进程至少包含一个线程。|

##### 3. 进程在内存中的布局 (Process Layout in Memory)

在更低的层面，即进程的虚拟地址空间中，其内容可以大致划分为：

|   |   |
|---|---|
|**内存区域 (Memory Area)**|**描述 (Description)**|
|**代码 (Code)**|进程执行的机器指令。|
|**全局变量 (Global Variables)**|存储程序中定义的全局变量和静态变量。|
|**进程堆 (Process Heap)**|用于动态内存分配的区域 (e.g., `malloc`, `new`)。|
|**进程栈 (Process Stack(s))**|每个线程都有自己的栈，用于存储局部变量、函数参数、返回地址等。 (原文作“进程资源”，但栈更具体)|
|**环境块 (Environment Block)**|存储进程的环境变量等信息的数据结构。|

##### 4. 观察进程：任务管理器及其他工具 (Observing Processes: Task Manager and Other Tools)

Windows 任务管理器是观察进程基本信息的一个常用工具。关键信息包括：

|   |   |   |
|---|---|---|
|**详细信息 (Detail)**|**描述 (Description)**|**示例 (Example)**|
|**名称 (Name)**|定义进程的名称，通常继承自其可执行文件名。|`conhost.exe`|
|**PID (Process ID)**|用于唯一标识进程的数字。|`7408`|
|**状态 (Status)**|确定进程的运行状态 (例如：正在运行 (Running), 已挂起 (Suspended) 等)。|`Running`|
|**用户名 (User Name)**|启动该进程的用户账户。这间接表示了进程所拥有的权限级别。|`SYSTEM`|

除了任务管理器，还有许多高级的进程观察和分析工具，例如：

- **Process Hacker 2**
- **Process Explorer (Sysinternals)**
- **Procmon (Process Monitor - Sysinternals)**

##### 5. 针对进程的攻击向量 (Attack Vectors Targeting Processes)

攻击者经常针对进程来规避检测、实现持久化或执行恶意代码，常利用以下技术 (参考 MITRE ATT&CK)：

- **进程注入 (Process Injection, T1055)**: 将代码注入到另一个活动进程的地址空间中执行。
    - **进程镂空 (Process Hollowing, T1055.012)**: 创建一个合法进程的挂起实例，将其内存替换为恶意代码，然后恢复执行。
- **进程伪装 (Process Masquerading, T1036.004 或相关子技术，原文为 T1055.013 但此ID已弃用，可能指代更广义的T1036下的技术)**: 将恶意软件伪装成合法或常见系统进程的名称或路径，以欺骗用户或安全软件。 (注意: T1055.013 指的是 Masquerading as User. 更相关的可能是 T1036.004 Masquerade Task or Service 或 T1036.005 Match Legitimate Name or Location)

---

#### 线程 (Threads)

##### 1. 定义与重要性 (Definition and Importance)

**线程 (Thread)** 是进程中负责执行代码的基本单元。一个进程可以拥有多个线程，这些线程并发执行，共享进程的资源（如内存地址空间、打开的句柄）。操作系统根据多种因素（如CPU可用性、内存、线程优先级、逻辑依赖等）来调度线程的执行。

可以简单地将线程理解为“控制进程执行流程的实体”。

##### 2. 线程的独有属性 (Unique Attributes of a Thread)

尽管线程共享其父进程的大部分资源（如代码段、全局变量），但每个线程也拥有一些独有的数据和状态：

|   |   |
|---|---|
|**组件 (Component)**|**描述 (Description)**|
|**栈 (Stack)**|用于存储线程的局部变量、函数调用参数、返回地址以及异常处理信息等。每个线程都有自己独立的栈。|
|**线程本地存储 (Thread Local Storage - TLS)**|一种机制，允许线程拥有其私有的数据存储区域，即使这些数据是通过全局或静态变量指针访问的。|
|**栈参数 (Stack Parameters)**|(此项原文表述较模糊，通常指线程创建时传递给线程函数的参数，或栈上为函数调用准备的参数) 每个线程在执行函数调用时，其栈上会保存特定的参数值。|
|**上下文结构 (Context Structure)**|包含线程的CPU寄存器状态（如指令指针、栈指针、通用寄存器等）。当线程被切换出或切换回CPU时，内核会保存或恢复其上下文结构。|

##### 3. 针对线程的攻击向量 (Attack Vectors Targeting Threads)

由于线程直接控制代码的执行，它们是攻击者常见的利用目标。线程滥用可以单独用于辅助代码执行，或与其他API调用链式结合，作为更复杂攻击技术的一部分（例如，在进程注入后创建远程线程执行Shellcode）。

---

#### 虚拟内存 (Virtual Memory)

##### 1. 定义与重要性 (Definition and Importance)

**虚拟内存 (Virtual Memory)** 是 Windows 内部运作的关键机制。它为每个进程提供了一个私有的、连续的地址空间（称为虚拟地址空间），使得进程认为自己独占了大量的内存，而无需关心物理内存的实际大小和布局。

- **隔离性**: 每个进程的虚拟地址空间是独立的，一个进程不能直接访问另一个进程的虚拟内存（除非通过共享内存等特殊机制），这增强了系统的稳定性和安全性。
- **地址转换**: 内存管理器 (Memory Manager) 负责将进程使用的虚拟地址转换为实际的物理内存地址。
- **分页/交换 (Paging/Swapping)**: 当物理内存不足时，内存管理器可以将部分不常用的虚拟内存页面（通常是4KB大小的块）保存到磁盘上的页面文件 (pagefile.sys) 中，称为“换出” (page out)。当需要访问这些页面时，再从磁盘加载回物理内存，称为“换入” (page in)。这使得系统可以运行比实际物理内存更大的应用程序。

##### 2. 虚拟地址空间布局 (Virtual Address Space Layout)

- **32位 (x86) 系统**:
    
    - 理论上最大虚拟地址空间为 4 GB。
    - 通常，低 2 GB (0x00000000 - 0x7FFFFFFF) 分配给用户模式进程使用。
    - 高 2 GB (0x80000000 - 0xFFFFFFFF) 保留给操作系统内核使用。
    - 管理员可以通过 `/3GB` 启动开关 (increaseUserVA) 或地址窗口化扩展 (Address Windowing Extensions - AWE) 来调整这种分配，以便某些需要大内存空间的应用程序可以使用接近 3GB 的用户空间内存 (AWE 则用于访问超过4GB的物理内存，但进程的虚拟地址空间仍受限)。
- **64位 (x64) 系统**:
    
    - 理论上最大虚拟地址空间非常巨大，例如在 Windows 上是 256 TB (用户模式和内核模式各128TB，具体数值可能随Windows版本变化)。
    - 这种巨大的地址空间基本解决了32位系统下用户空间不足的问题，因此 `/3GB` 开关或 AWE 对于增加单个进程的虚拟地址空间的需求已不那么迫切。

理解虚拟内存的概念对于深入利用 Windows 内部机制至关重要，例如在进行内存分析、漏洞利用开发或实现某些高级注入技术时。

---

#### 动态链接库 (Dynamic Link Libraries - DLLs)

##### 1. 定义与重要性 (Definition and Importance)

微软文档将 **DLL (Dynamic Link Library)** 描述为“一个包含代码和数据的库，可以被多个程序同时使用。” DLL 是实现代码模块化、代码重用、高效内存使用和减少磁盘空间的关键机制。

- **代码重用**: 多个应用程序可以共享同一个 DLL 中的函数和资源。
- **模块化**: 可以将应用程序的功能划分为不同的 DLL，便于开发和维护。
- **内存效率**: 当多个进程加载同一个 DLL 时，操作系统通常会将 DLL 的代码段在物理内存中映射一份共享实例。

##### 2. DLL 的加载方式 (How DLLs are Loaded)

DLL 可以在程序中通过以下两种主要方式加载：

- **加载时动态链接 (Load-Time Dynamic Linking)**:
    
    - 应用程序在编译链接时就声明了对某个 DLL 中函数的依赖。
    - 需要提供 DLL 的头文件 (`.h`) 和导入库文件 (`.lib`) 给链接器。
    - 当应用程序启动时，Windows 加载器会自动加载所需的 DLL，并解析函数地址。
    - **示例 (C++)**:
        
        C++
        
        ```
        // main.cpp
        #include "stdafx.h" // 通常是预编译头
        #include "sampleDLL.h" // 假设 sampleDLL.h 声明了 HelloWorld()
        
        int APIENTRY WinMain(HINSTANCE hInstance,
                             HINSTANCE hPrevInstance,
                             LPSTR     lpCmdLine,
                             int       nCmdShow)
        {
            HelloWorld(); // 直接调用 DLL 中的函数
            return 0;
        }
        ```
        
- **运行时动态链接 (Run-Time Dynamic Linking)**:
    
    - 应用程序在运行时使用特定 API 函数（如 `LoadLibrary` 或 `LoadLibraryEx`）来显式加载 DLL。
    - 加载成功后，使用 `GetProcAddress` API 来获取 DLL 中导出函数的地址。
    - 这种方式更灵活，允许程序根据需要加载或卸载 DLL。
    - **示例 (C++)**:
        
        C++
        
        ```
        // main.cpp
        // ...
        typedef VOID (*DLLPROC)(VOID); // 定义函数指针类型 (假设 HelloWorld 无参数无返回值)
        // ...
        
        HINSTANCE hinstDLL;
        DLLPROC HelloWorldFunc; // 函数指针变量
        BOOL fFreeDLL;
        
        hinstDLL = LoadLibrary(TEXT("sampleDLL.dll")); // 加载 DLL
        if (hinstDLL != NULL)
        {
            HelloWorldFunc = (DLLPROC)GetProcAddress(hinstDLL, "HelloWorld"); // 获取函数地址
            if (HelloWorldFunc != NULL)
            {
                (HelloWorldFunc)(); // 通过函数指针调用
            }
            fFreeDLL = FreeLibrary(hinstDLL); // 卸载 DLL
        }
        // ...
        ```
        

在恶意代码中，攻击者通常更倾向于使用**运行时动态链接**，因为它更灵活，便于隐藏依赖关系，并且在内存中操作单个 DLL 文件比处理多个依赖文件（如导入库）更容易。

##### 3. DLL 创建示例 (DLL Creation Example)

DLL 的创建与普通应用程序项目类似，但需要特定的导出声明。

- **DLL 源码 (`sampleDLL.cpp`)**:
    
    C++
    
    ```
    #include "stdafx.h" // 通常用于 Visual C++ 项目
    #define EXPORTING_DLL // 自定义宏，用于条件编译导出声明
    #include "sampleDLL.h"
    #include <windows.h> // For MessageBox
    
    // DLL 入口点函数 (可选，但常见)
    BOOL APIENTRY DllMain( HANDLE hModule,      // DLL 模块句柄
                           DWORD  ul_reason_for_call, // 调用原因
                           LPVOID lpReserved)     // 保留参数
    {
        switch (ul_reason_for_call)
        {
            case DLL_PROCESS_ATTACH: // DLL 被加载到进程地址空间
            case DLL_THREAD_ATTACH:  // 新线程创建
            case DLL_THREAD_DETACH:  // 线程正常退出
            case DLL_PROCESS_DETACH: // DLL 从进程地址空间卸载
                break;
        }
        return TRUE; // 初始化成功
    }
    
    // 导出的函数
    // EXPORTING_DLL 宏用于在 sampleDLL.h 中切换 __declspec(dllexport) 和 __declspec(dllimport)
    void HelloWorld()
    {
        MessageBox( NULL, TEXT("Hello World"), TEXT("In a DLL"), MB_OK);
    }
    ```
    
- **DLL 头文件 (`sampleDLL.h`)**: 定义导入和导出函数。
    
    C++
    
    ```
    #ifndef SAMPDLL_H // 避免重复包含的 Include Guard
    #define SAMPDLL_H
    
    #ifdef EXPORTING_DLL // 由 DLL 项目自身定义
        #define DECLSPEC_DLL __declspec(dllexport) // 声明为导出
    #else
        #define DECLSPEC_DLL __declspec(dllimport) // 声明为导入 (供使用此 DLL 的程序使用)
    #endif
    
    // 声明导出的 HelloWorld 函数
    extern "C" DECLSPEC_DLL void HelloWorld(); // extern "C" 避免 C++ 名称修饰
    
    #endif
    ```
    

##### 4. 针对 DLL 的攻击向量 (Attack Vectors Targeting DLLs)

由于 DLL 在程序执行中的核心作用和依赖关系，攻击者常利用它们进行恶意活动：

- **DLL 劫持 (DLL Hijacking, T1574.001)**: 利用应用程序加载 DLL 时的搜索顺序，将恶意 DLL 放置在优先搜索路径中，使其被合法程序加载执行。
- **DLL 侧加载 (DLL Side-Loading, T1574.002)**: 将恶意 DLL 与合法应用程序捆绑在一起，当合法程序运行时，它会加载并执行同目录下的恶意 DLL（如果程序设计为优先从当前目录加载）。
- **DLL 注入 (DLL Injection, T1055.001)**: (T1055 的子技术) 将恶意 DLL 强制加载到目标进程的地址空间中执行。这是进程注入的一种常见形式。

---

#### 可移植可执行文件格式 (Portable Executable - PE Format)

##### 1. 定义与重要性 (Definition and Importance)

**PE (Portable Executable) 格式** 是 Windows 操作系统中用于可执行文件 (`.exe`)、对象代码 (`.obj`)、动态链接库 (`.dll`) 等的标准文件格式。它定义了这些文件的结构，使得操作系统加载器能够正确解析文件内容、映射到内存并执行。PE 格式源于 COFF (Common Object File Format) 格式。

##### 2. PE 文件结构 (PE File Structure)

PE 文件的结构可以从高到低分为以下几个主要部分，这些部分通常可以在十六进制编辑器中观察到：

1. **DOS 头 (MS-DOS Header)**:
    
    - 位于文件开头，用于兼容 MS-DOS 系统。
    - 包含一个 DOS MZ 可执行文件存根 (DOS stub)，通常会打印一条消息如 "This program cannot be run in DOS mode."
    - 最重要的是 `e_lfanew` 字段，它是一个偏移量，指向 PE 文件头 (`IMAGE_NT_HEADERS`) 的位置。
    - 以幻数 `MZ` (0x4D5A) 开头。
2. **DOS 存根 (DOS Stub)**:
    
    - 紧跟在 DOS 头之后的一个小程序，如果文件在 DOS 环境下运行，则会执行此存根。
3. **PE 文件头 (PE File Header - `IMAGE_NT_HEADERS`)**:
    
    - 这是 PE 格式的核心部分，包含了关于文件的重要信息。
    - 以签名 `PE\0\0` (0x50450000) 开头。
    - `IMAGE_NT_HEADERS` 结构包含：
        - **签名 (Signature)**: 即 "PE\0\0"。
        - **文件头 (`IMAGE_FILE_HEADER`)**: 包含文件的基本信息，如目标机器类型 (x86, x64, ARM)、节 (Section) 的数量、时间戳、指向符号表的指针、可选头的大小以及文件特性 (如是否为DLL、是否可执行等)。
        - **可选头 (`IMAGE_OPTIONAL_HEADER`)**: (虽然名为“可选”，但对于可执行文件是必需的) 包含更详细的加载信息。其结构根据是32位 (PE32) 还是64位 (PE32+) 而略有不同。
            - **标准字段**: 如幻数 (0x10B for PE32, 0x20B for PE32+), 链接器版本, 代码大小, 初始化数据大小, 入口点地址 (AddressOfEntryPoint), 代码基址 (BaseOfCode), 映像基址 (ImageBase) 等。
            - **Windows 特定字段**: 如子系统 (GUI, CUI), DLL 特性, 栈和堆的保留及提交大小等。
            - **数据目录 (`IMAGE_DATA_DIRECTORY` 数组)**: 一个包含16个元素的数组（数量可能变化），每个元素指向一个重要的数据结构，如导入表、导出表、资源表、重定位表、调试信息等。每个目录项包含该结构的虚拟地址 (RVA) 和大小。
4. **节表 (Section Table - `IMAGE_SECTION_HEADER` 数组)**:
    
    - 紧跟在 `IMAGE_NT_HEADERS` 之后。
    - 是一个 `IMAGE_SECTION_HEADER` 结构的数组，每个结构描述文件中的一个节 (Section)。
    - 每个节头包含节的名称 (如 `.text`, `.data`)、虚拟大小、在内存中的相对虚拟地址 (RVA)、在文件中的原始数据大小和偏移量、节的特性 (如是否包含代码、是否可读/可写/可执行) 等。
5. **节数据 (Section Data)**:
    
    - 实际的文件内容，按照节表中定义的布局存储。常见的节包括：
        - **.text (或 .code)**: 包含可执行代码，通常包括程序入口点。
        - **.data**: 包含已初始化的全局变量和静态变量。
        - **.rdata (或 .idata)**: 通常包含只读数据，如字符串常量。导入表 (Import Address Table - IAT) 通常也位于此节或一个专门的 `.idata` 节。
        - **.reloc**: 包含基址重定位信息，用于在映像加载到非默认基址时修正绝对地址引用。
        - **.rsrc**: 包含应用程序资源，如图标、菜单、对话框模板、版本信息等。
        - **.debug**: 包含调试信息（如果存在）。
        - **.edata**: 导出表，列出 DLL 导出的函数和变量。
        - **.tls**: 线程本地存储。

理解 PE 格式对于逆向工程、恶意软件分析、加壳/脱壳技术以及开发调试工具等领域至关重要。

---

#### 与 Windows 内部交互 (Interacting with Windows Internals)

##### 1. 交互方式：Windows API (Interaction Method: Windows API)

与 Windows 内部组件进行交互的最直接且最受支持的方式是通过 **Windows API**。Windows API 提供了一组丰富的函数，允许用户模式应用程序请求操作系统内核执行各种操作，从而间接与硬件和受保护的系统资源交互。这包括了前面讨论过的 Win32 API (主要用于32位和64位应用程序) 和其他相关API。

##### 2. 处理器模式与切换 (Processor Modes and Switching)

回顾一下，Windows 使用两种处理器模式：

- **用户模式 (User Mode)**:
    - 应用程序运行在此模式。
    - 没有直接硬件访问权限。
    - 进程拥有私有的虚拟地址空间。
    - 对内存的访问受限。
- **内核模式 (Kernel Mode)**:
    - 操作系统核心组件和设备驱动程序运行在此模式。
    - 拥有直接硬件访问权限。
    - 所有内核代码运行在一个共享的虚拟地址空间。
    - 可以访问整个物理内存。

当用户模式应用程序需要执行特权操作（如访问硬件、修改关键系统设置或与其他进程的受保护内存交互）时，它必须通过**系统调用 (System Call)** 来请求内核服务。Windows API 函数通常封装了这些系统调用。当 API 调用发生时，处理器会从用户模式切换到内核模式执行请求，完成后再切换回用户模式并将结果返回给应用程序。这个切换点是操作系统安全模型的核心。

当编程语言（如 C#）通过其运行时环境（如 .NET CLR）与 Win32 API 交互时，调用链可能是：应用程序代码 -> 语言运行时 -> Win32 API -> 系统调用 -> 内核模式执行。

##### 3. 示例：通过 API 进行进程注入 (Example: Process Injection via API)

以下步骤和 API 调用展示了如何将一个简单的消息框注入到另一个本地进程中执行，这是一个与内存和进程交互的典型概念验证：

1. 获取目标进程句柄 (OpenProcess):
    
    首先需要获取目标进程的句柄，并请求必要的访问权限（如创建远程线程、写入内存、分配内存）。
    
    C++
    
    ```
    // 假设 argv[1] 是目标进程的 PID 字符串
    // DWORD targetPID = atoi(argv[1]); // 将命令行参数（PID）转换为整数
    // HANDLE hProcess = OpenProcess(
    //     PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, // 请求所有必要权限
    //     FALSE,              // 子进程不继承此句柄
    //     targetPID           // 目标进程的 PID
    // );
    // if (hProcess == NULL) { /* 错误处理 */ }
    ```
    
    原文示例：`PROCESS_ALL_ACCESS` 请求了所有权限，这在实际中可能过于宽泛，且可能需要高权限才能成功。
    
2. 在目标进程中分配内存 (VirtualAllocEx):
    
    在目标进程的虚拟地址空间中为要注入的代码（这里是显示消息框的 Shellcode，或 DLL 路径）分配一块内存区域。
    
    C++
    
    ```
    // LPVOID remoteBuffer; // 用于存储远程分配的内存地址
    // char payload[] = "Path_to_your_messagebox_displaying_DLL_or_shellcode"; // 示例载荷
    // remoteBuffer = VirtualAllocEx(
    //     hProcess,           // 目标进程句柄
    //     NULL,               // 让系统选择分配地址
    //     sizeof(payload),    // 分配的内存大小
    //     MEM_RESERVE | MEM_COMMIT, // 保留并提交页面
    //     PAGE_EXECUTE_READWRITE  // 内存保护属性：可读、可写、可执行
    // );
    // if (remoteBuffer == NULL) { /* 错误处理 */ }
    ```
    
3. 将载荷写入已分配的内存 (WriteProcessMemory):
    
    将要执行的代码或数据（如 DLL 路径或 Shellcode）从当前进程复制到目标进程中新分配的内存区域。
    
    C++
    
    ```
    // SIZE_T bytesWritten;
    // if (!WriteProcessMemory(
    //     hProcess,           // 目标进程句柄
    //     remoteBuffer,       // 目标进程中已分配的内存地址
    //     payload,            // 要写入的数据（来自当前进程）
    //     sizeof(payload),    // 要写入的字节数
    //     &bytesWritten       // （可选）接收实际写入的字节数
    // )) { /* 错误处理 */ }
    ```
    
4. 在目标进程中创建远程线程执行载荷 (CreateRemoteThread):
    
    在目标进程中创建一个新线程，该线程的起始执行地址指向刚刚写入的载荷。如果载荷是 Shellcode，则直接执行；如果是 DLL 路径，则通常将 LoadLibraryA/W 的地址作为线程起始地址，DLL 路径作为参数传递给 LoadLibrary。
    
    C++
    
    ```
    // HANDLE hRemoteThread;
    // hRemoteThread = CreateRemoteThread(
    //     hProcess,           // 目标进程句柄
    //     NULL,               // 默认线程安全属性
    //     0,                  // 默认栈大小
    //     (LPTHREAD_START_ROUTINE)remoteBuffer, // 线程起始地址（指向载荷）
    //                                         // 如果是注入DLL，这里通常是 LoadLibraryA/W 的地址
    //     remoteBuffer,       // （可选）传递给线程函数的参数（如果是 LoadLibrary，这里是 DLL 路径的地址）
    //                                         // 原文示例中这个参数是 NULL，若 remoteBuffer 指向的是可直接执行的 shellcode 则可以
    //     0,                  // 线程立即运行
    //     NULL                // （可选）接收线程ID
    // );
    // if (hRemoteThread == NULL) { /* 错误处理 */ }
    // else { CloseHandle(hRemoteThread); /* 清理线程句柄 */ }
    // CloseHandle(hProcess); /* 清理进程句柄 */
    ```