### 概述

服务器端模板注入（Server-Side Template Injection, SSTI）是一种Web安全漏洞，发生在应用程序将用户提供的输入不安全地嵌入到服务器端的模板引擎中进行处理时。由于模板引擎通常设计用来执行代码以生成动态内容，注入恶意构造的输入可能导致攻击者在服务器上执行任意代码。这可能引发一系列严重后果，包括但不限于信息泄露（如环境变量、配置文件、源代码）、权限提升、文件系统访问、执行系统命令，甚至完全控制服务器或导致拒绝服务（DoS）。

SSTI 漏洞常见于使用模板引擎（如 Jinja2, Twig, Smarty, Pug, Velocity, Freemarker 等）动态生成HTML、邮件或其他文本内容的Web应用程序中。

### 模板引擎基础

可以把模板引擎想象成一个自动生成个性化内容的工具。

1.  **工作原理类比:** 就像制作生日贺卡，你不会为每个人从零开始写，而是使用一个模板，上面有预留的位置（占位符）来填写名字、年龄和祝福语。
2.  **模板引擎流程:**
    *   **模板 (Template):** 包含静态内容和特殊标记（占位符、逻辑结构）的预定义文件或字符串。例如：`Hello, {{ username }}!`
    *   **数据 (Context/Input):** 应用程序准备的动态数据，通常包含用户输入或从数据库查询的结果。例如：`{'username': 'Alice'}`
    *   **渲染 (Rendering):** 模板引擎将模板和数据结合起来，解析模板中的特殊标记，用实际数据替换占位符，并执行其中的逻辑。
    *   **输出 (Output):** 生成最终的、动态的内容（通常是HTML）。例如：`Hello, Alice!`
3.  **与SSTI的关系:** 许多模板引擎允许在模板中嵌入表达式，用于执行简单的计算、条件判断或函数调用。如果用户输入未经充分验证和清理就被当作模板代码的一部分来处理，攻击者就可以注入包含恶意表达式的输入，这些表达式会被模板引擎执行，从而导致SSTI。

### SSTI 攻击原理与流程

SSTI的核心在于服务器端模板引擎对**用户输入的不当处理**。

1.  **动态内容生成被利用:** 模板引擎处理动态内容的过程被攻击者劫持。
2.  **用户输入被当作模板代码:** 当应用程序直接将用户输入（例如，URL参数、表单字段、HTTP头）嵌入模板字符串中，而没有进行适当的转义或隔离时，这些输入可能被模板引擎误解为可执行的模板指令。
3.  **攻击流程:**
    *   攻击者向应用程序提交包含特定模板语法的恶意输入。
    *   应用程序未经过滤或转义，将此输入嵌入到服务器端的模板中。
    *   模板引擎在渲染模板时，解析并执行了攻击者注入的恶意模板代码。
    *   这导致了非预期的服务器端操作，例如：
        *   读取或写入服务器上的敏感文件。
        *   执行任意操作系统命令。
        *   访问和泄露应用程序内部变量、配置或凭证。
        *   调用应用程序内部的危险函数或方法。
        *   发起对内部网络或其他服务的请求 (SSRF)。

### 检测模板引擎

由于不同的模板引擎使用不同的语法和内置对象，识别目标应用程序使用的具体模板引擎是成功利用SSTI的第一步。可以通过注入包含不同引擎特有语法的测试 Payload，并观察输出来判断。

*   **区分 Jinja2 (Python) / Twig (PHP):**
    *   Payload: `{{7*'7'}}`
    *   **Twig 输出:** `49` (执行数学乘法)
    *   **Jinja2 输出:** `7777777` (执行字符串重复)
*   **识别 Jade/Pug (Node.js):**
    *   Payload: `#{7*7}`
    *   **Pug/Jade 输出:** `49` (在 `#{}` 内执行 JavaScript 表达式)
*   **识别 Smarty (PHP):**
    *   Payload: `{'Hello'|upper}` 或 `{literal}Hello{/literal}{* comment *}` 或直接尝试 `{php}phpinfo();{/php}` (如果允许)
    *   **Smarty 输出:** `HELLO` 或正常显示 `Hello` 或执行了 PHP 代码。
*   **其他通用探测 Payload:**
    *   `<%= 7*7 %>` (ERB - Ruby)
    *   `${7*7}` (Freemarker - Java, Mako - Python)
    *   `@{7*7}` (Razor - .NET)
    *   `*{7*7}` (Thymeleaf - Java)

通常可以通过发送一系列包含不同语法特征的数学运算或字符串操作的 Payload 来缩小范围或确定模板引擎。

### 特定模板引擎的利用

#### PHP - Smarty

*   **简介:** Smarty 是一个流行的 PHP 模板引擎，旨在将表示层（HTML）与应用程序逻辑（PHP）分离。
*   **漏洞点:** 如果配置不当（特别是允许使用 `{php}` 标签或通过插件/修饰符执行任意 PHP 函数），Smarty 可能容易受到 SSTI 攻击。默认配置通常是安全的。
*   **确认/检测:**
    *   注入简单的 Smarty 标签，如 `{'Hello'|upper}`。如果输出为 `HELLO`，则确认是 Smarty。
    *   尝试 `{self::version}` 查看 Smarty 版本。
*   **利用 (假设允许执行 PHP 函数):**
    *   **Payload:** `{system("id")}` 或 `{exec("whoami")}`
    *   **原理:** 直接利用 Smarty 模板调用 PHP 的 `system()` 或 `exec()` 函数执行操作系统命令。
    *   **前提:** Smarty 的安全设置必须允许直接调用这些 PHP 函数，或者存在允许间接调用的自定义函数/修饰符。现代 Smarty 版本默认禁用 `{php}` 标签，并提供了安全模式。

#### Node.js - Pug (原名 Jade)

*   **简介:** Pug 是 Node.js 生态中广泛使用的高性能模板引擎，以其简洁的缩进式语法和强大的功能（条件、循环、Mixin）著称。
*   **漏洞点:** Pug 允许通过 `#{}` 或 `!{}` 语法在模板中直接嵌入和执行 JavaScript 代码。如果用户输入未经清理就被插入到这些插值表达式中，或者插入到模板结构本身，就可能导致任意 JavaScript 执行，进而可能调用 Node.js API 执行系统命令。
*   **确认/检测:**
    *   注入 `#{7*7}`。如果输出为 `49`，则确认是 Pug。
*   **利用 (执行系统命令):**
    *   **Payload:**
        ```pug
        #{process.mainModule.require('child_process').spawnSync('id').stdout}
        ```
        或者带参数的（推荐方式）：
        ```pug
        #{process.mainModule.require('child_process').spawnSync('ls', ['-lah']).stdout}
        ```
    *   **Payload 分解:**
        1.  `process`: 访问 Node.js 的全局 `process` 对象。
        2.  `mainModule`: (可能因 Node 版本而异，有时需用 `process.mainModule` 或其他方式找到主模块) 访问应用程序的主模块。
        3.  `require('child_process')`: 动态加载 Node.js 的 `child_process` 模块，该模块用于创建子进程。
        4.  `spawnSync('command', [args])`: 同步执行指定的系统命令 (`'id'` 或 `'ls'`)，并将参数 (`['-lah']`) 作为数组传递。同步执行意味着 Node.js 会等待命令完成。
        5.  `.stdout`: 获取命令执行后的标准输出内容。
    *   **重要：命令与参数分离 (`spawnSync` / `execSync` 等):**
        *   **错误用法:** `spawnSync('ls -lah')`。将整个命令和参数作为一个字符串传递，`spawnSync` 会尝试执行名为 "ls -lah" 的文件，而不是带参数的 `ls` 命令，导致执行失败。
        *   **正确用法:** `spawnSync('ls', ['-lah'])`。将命令 (`'ls'`) 和参数数组 (`['-lah']`) 分开传递。这是 Node.js `child_process` 模块推荐的安全做法，有助于防止命令注入（Shell Injection）漏洞。

#### Python - Jinja2

*   **简介:** Jinja2 是 Python Web 开发（尤其是 Flask 和 Django 框架）中最流行的模板引擎之一，以其功能强大、速度快和类似 Python 的语法而闻名。
*   **漏洞点:** Jinja2 允许在 `{{ }}` 表达式中执行 Python 代码片段。如果用户输入未经清理就被直接放入模板中，攻击者可以构造恶意表达式来访问 Python 的内置函数、对象和模块，最终可能导致任意代码执行。漏洞通常源于开发者如何使用 Jinja2，而非引擎本身。
*   **确认/检测:**
    *   注入 `{{7*7}}`。如果输出为 `49`，则可能是 Jinja2 (或其他支持类似语法的引擎，需结合其他 payload 进一步区分，如 `{{7*'7'}}` 输出 `7777777`)。
*   **利用 (执行系统命令):**
    *   **Payload (常见的基于对象遍历):**
        ```jinja2
        {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
        ```
        或者更通用的（通过查找 `subprocess.Popen` 等）：
        ```jinja2
        {{ ''.__class__.__mro__[1].__subclasses__()[XYZ].__init__.__globals__['__builtins__']['__import__']('subprocess').check_output(['ls','-lah']) }}
        ```
        *(注意: `[XYZ]` 处的索引号需要根据目标环境确定，它代表 `subprocess.Popen` 或类似危险子类在 `object` 的 `__subclasses__()` 列表中的位置，可以通过爆破或信息泄露获得)*
    *   **Payload 分解 (以 `subprocess` 为例):**
        1.  `''.__class__`: 获取空字符串的类 (`<class 'str'>`)。
        2.  `.__mro__[1]`: 访问其方法解析顺序 (Method Resolution Order) 中的父类，通常是基类 `object` (`<class 'object'>`)。
        3.  `.__subclasses__()`: 获取 `object` 类的所有直接和间接子类列表。这是一个包含大量 Python 类的列表。
        4.  `[XYZ]`: 通过索引选择一个潜在有用的子类，如 `subprocess.Popen`（用于执行命令）。**此索引在不同 Python 环境和版本中会变化，需要探测。**
        5.  `.__init__.__globals__['__builtins__']['__import__']`: 通过一系列属性访问，最终获取到 Python 的内置 `__import__` 函数，用于动态导入模块。
        6.  `('subprocess')`: 使用 `__import__` 导入 `subprocess` 模块。
        7.  `.check_output(['ls','-lah'])`: 调用 `subprocess` 模块的 `check_output` 函数执行命令，并返回其标准输出。
    *   **重要：命令与参数分离 (`subprocess.check_output` / `subprocess.run` 等):**
        *   **错误用法:** `check_output('ls -lah', shell=True)` (虽然可行，但 `shell=True` 开启了 shell 解析，极易引入 Shell 注入风险，应避免)。直接 `check_output('ls -lah')` 不会按预期工作。
        *   **正确用法:** `check_output(['ls', '-lah'])`。将命令和参数作为列表传递，这是 `subprocess` 模块推荐的安全方式，避免了 shell 注入风险。

### 自动化利用工具

*   **SSTImap:** 一个流行的开源 Python 工具，专门用于自动化检测和利用 SSTI 漏洞。
    *   **功能:**
        *   自动检测多种模板引擎。
        *   测试注入点。
        *   提供利用模块以执行命令、读写文件等。
    *   **安装与使用:**
        ```bash
        # 克隆仓库
        git clone https://github.com/vladko312/SSTImap.git
        cd SSTImap
        # 安装依赖 (通常需要 Python 3)
        pip install -r requirements.txt # 或者 pip3 install -r requirements.txt

        # 基本用法示例 (POST 请求，注入 'page' 参数)
        python3 sstimap.py -u "http://target.com/vulnerable_page" -X POST -d "page=INJECT_HERE"
        # 或者指定参数注入
        python3 sstimap.py -u "http://target.com/?name=INJECT_HERE"
        ```
    *   SSTImap 会尝试各种 payload 来识别引擎并进行利用。

### 防御措施

防御 SSTI 的关键在于**阻止用户输入被当作模板代码执行**，并限制模板引擎的能力。

1.  **选择安全的模板引擎或配置:**
    *   优先选用默认配置安全、不易被误用导致 SSTI 的模板引擎。
    *   了解并利用模板引擎提供的安全特性。

2.  **输入清理与验证 (Sanitization & Validation):**
    *   **永不将未经验证的用户输入直接嵌入模板字符串中。**
    *   对所有用户输入进行严格的验证，确保其符合预期的格式、类型和范围。
    *   使用白名单方法，只允许已知的安全字符或模式。
    *   对需要在模板中显示的输入进行**上下文感知**的转义（例如，在 HTML 上下文中使用 HTML 实体编码）。**注意：** 简单的 HTML 转义通常不足以防御 SSTI，因为注入发生在服务器端模板解析阶段，而非浏览器渲染阶段。

3.  **避免将用户输入用作模板逻辑的一部分:**
    *   不要让用户输入决定模板文件名、要包含的子模板、要调用的函数名或模板内的条件逻辑。

4.  **使用沙箱 (Sandboxing):**
    *   **核心机制:** 许多现代模板引擎提供沙箱模式，它创建一个受限的执行环境，限制模板可以访问的函数、方法、属性和模块。
    *   **重要性:** 沙箱是防御 SSTI 的**强有力措施**。它可以阻止模板执行危险操作（如文件 I/O、系统命令、网络请求、访问敏感对象）。
    *   **实现 (示例):**
        *   **Jinja2:** 使用 `SandboxedEnvironment`。
            ```python
            from jinja2 import Environment, select_autoescape, sandbox
            # 创建沙箱环境
            env = sandbox.SandboxedEnvironment(autoescape=select_autoescape(['html', 'xml']))
            # 使用 env 渲染模板
            ```
        *   **Twig:** Twig 默认就有一定的安全策略，可以通过扩展 `SecurityPolicy` 来进一步定制沙箱规则。
        *   **Smarty:** 提供了 `Security` 类来限制对 PHP 函数、静态类等的访问。
    *   **配置:** 仔细配置沙箱，确保只允许模板执行绝对必要且安全的操作。

5.  **特定引擎建议:**
    *   **Jinja2:** 强烈推荐使用 `SandboxedEnvironment`。定期审计模板，避免不安全的模式。
    *   **Pug:** 避免使用 `!{}` 进行未转义的插值，除非绝对必要且输入已严格清理。谨慎使用 `#{}`，确保插入其中的 JavaScript 不受用户输入影响。验证和清理所有传入模板的数据。
    *   **Smarty:** **禁用 `{php}` 标签** (`$smarty->setPhpHandling(Smarty::PHP_REMOVE);`)。使用 `Security` 类限制模板能力。避免创建允许执行任意 PHP 代码的自定义函数或修饰符。定期更新 Smarty 版本。

6.  **保持更新与安全审计:**
    *   及时更新模板引擎库及其依赖项，以获取最新的安全补丁。
    *   定期进行代码审计和安全测试，检查是否存在 SSTI 漏洞。