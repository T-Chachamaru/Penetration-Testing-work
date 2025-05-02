### 概述 (Overview)

在动态的网络安全领域，渗透测试人员和开发者持续探索各种漏洞，其中**原型污染 (Prototype Pollution)** 是一个日益受到关注的概念。这种漏洞允许恶意行为者操纵 JavaScript 应用程序的内部对象结构，特别是对象的**原型 (prototype)**，从而可能影响应用程序的行为，甚至访问敏感数据或控制后端逻辑。

虽然原型污染的概念理论上可以应用于任何使用类似原型继承模型的语言，但它在 **JavaScript** 中尤为突出和危险。这主要归因于：

*   **JavaScript 的广泛应用**: 尤其是在前端和后端（Node.js）Web 开发中。
*   **灵活和动态的对象模型**: JavaScript 允许在运行时修改对象的原型，这种特性为污染提供了可能。

相比之下，像 Java 或 C++ 这样的基于类的语言，其继承模型通常是静态的，在运行时修改类的结构以影响所有实例并非易事或常规操作。

原型污染本身可能不直接构成最高威胁，但当它与其他漏洞（如**跨站脚本 Cross-Site Scripting, XSS** 或**跨站请求伪造 Cross-Site Request Forgery, CSRF**）结合时，其潜在危害会显著放大。

### JavaScript 基础回顾 (JavaScript Fundamentals Refresher)

理解原型污染需要掌握 JavaScript 的一些核心概念：

#### 1. 对象 (Objects)

*   **定义**: JavaScript 中的对象是键值对的集合，可以看作是存储相关信息的容器。
*   **示例**: 一个用户社交资料可以表示为一个对象。
    ```javascript
    let user = {
      name: 'Ben S',
      age: 25,
      followers: 200,
      DoB: '1/1/1990' // Date of Birth
    };
    // 访问属性: user.name 或 user['name']
    ```
    对象是构建动态应用的基础，用于组织和管理数据。

#### 2. 类 (Classes) - ES6 语法糖

*   **定义**: ES6 引入的 `class` 语法提供了一种更清晰、更面向对象的方式来创建对象的“蓝图”。类定义了对象的结构（属性）和行为（方法）。
*   **作用**: 便于创建具有相似结构和行为的多个对象实例。
*   **示例**: 定义用户和内容创作者的类。
    ```javascript
    // 用户资料类
    class UserProfile {
      constructor(name, age, followers, dob) {
        this.name = name;
        this.age = age;
        this.followers = followers;
        this.dob = dob;
      }

      greet() {
        return `Hello, ${this.name}!`;
      }
    }

    // 内容创作者资料类，继承自 UserProfile
    class ContentCreatorProfile extends UserProfile {
      constructor(name, age, followers, dob, content, posts) {
        super(name, age, followers, dob); // 调用父类的构造函数
        this.content = content;
        this.posts = posts;
      }
    }

    // 创建实例
    let regularUser = new UserProfile('Ben S', 25, 1000, '1/1/1990');
    let contentCreator = new ContentCreatorProfile('Jane Smith', 30, 5000, '1/1/1990', 'Engaging Content', 50);

    console.log(regularUser.greet()); // 输出: Hello, Ben S!
    console.log(contentCreator.name); // 输出: Jane Smith (继承自 UserProfile)
    ```
*   **注意**: JavaScript 的类本质上是基于**原型继承**的语法糖。底层机制仍然是原型。

#### 3. 原型 (Prototypes)

*   **定义**: 在 JavaScript 中，几乎每个对象都有一个内部链接指向另一个对象，这个对象就是它的**原型**。原型对象本身也有自己的原型，依此类推，形成一个**原型链 (prototype chain)**。
*   **作用**: 当试图访问一个对象的属性或方法时，如果对象本身没有定义，JavaScript 会沿着原型链向上查找，直到找到该属性/方法或到达链的末端（通常是 `Object.prototype`，其原型为 `null`）。这实现了**继承**。
*   **访问原型**:
    *   `Object.getPrototypeOf(obj)`: 标准方法获取对象的原型。
    *   `obj.__proto__`: 非标准但广泛实现的属性，直接访问对象的原型（不推荐在生产代码中使用，但在漏洞利用中常见）。
    *   `ConstructorFunction.prototype`: 构造函数的 `prototype` 属性指向当使用 `new ConstructorFunction()` 创建对象时，这些新对象的原型。
*   **示例 (使用构造函数和原型)**:
    ```javascript
    // 定义原型对象，包含共享方法
    let userPrototype = {
      greet: function() {
        return `Hello, ${this.name}!`;
      }
    };

    // 构造函数
    function UserProfilePrototype(name, age, followers, dob) {
      // 1. 创建一个新对象，其原型是 userPrototype
      let user = Object.create(userPrototype);
      // 2. 设置实例自身的属性
      user.name = name;
      user.age = age;
      user.followers = followers;
      user.dob = dob;
      // 3. 返回这个新对象
      return user;
    }

    // 创建实例
    let regularUser = UserProfilePrototype('Ben S', 25, 1000, '1/1/1990');

    // 调用继承自原型的方法
    console.log(regularUser.greet()); // 输出: Hello, Ben S!
    // 检查原型
    console.log(Object.getPrototypeOf(regularUser) === userPrototype); // 输出: true
    ```

#### 4. 继承 (Inheritance)

*   **定义**: 允许一个对象（子对象）获取另一个对象（父对象或原型）的属性和方法。
*   **实现方式**:
    *   **基于原型 (Prototypal Inheritance)**: 使用 `Object.create()` 或直接操作 `prototype` 属性。对象直接从其他对象继承。
    *   **基于类 (Classical Inheritance - 语法糖)**: 使用 `class` 和 `extends` 关键字。虽然语法像类，但底层仍是原型继承。
*   **示例 (基于原型)**:
    ```javascript
    let UserProfile = {
      email: 'default@example.com',
      password: 'password123' // (不应这样存储密码，仅作示例)
    };

    // 创建 ContentCreatorProfile，其原型是 UserProfile
    let ContentCreatorProfile = Object.create(UserProfile);
    ContentCreatorProfile.posts = 50; // 添加自己的属性

    // 访问属性
    console.log(ContentCreatorProfile.posts); // 输出: 50 (自身属性)
    console.log(ContentCreatorProfile.email); // 输出: default@example.com (继承自原型 UserProfile)
    ```
    当访问 `ContentCreatorProfile.email` 时，由于 `ContentCreatorProfile` 自身没有 `email` 属性，JavaScript 会查找其原型 `UserProfile` 并找到该属性。

### 原型污染的工作原理 (How Prototype Pollution Works)

原型污染漏洞发生在攻击者能够**修改 JavaScript 对象的原型**时。由于 JavaScript 的继承机制，对原型对象的修改会**影响所有继承自该原型的对象实例**，以及未来创建的实例。

**核心思想**: 如果攻击者能控制用于设置对象属性的代码，并设法将属性设置在对象的原型（通常是通过 `__proto__` 或有时是 `constructor.prototype`）上，而不是对象实例本身，那么这个新属性或被修改的方法就会“污染”所有共享该原型的对象。

**一个常见示例**:

假设有以下代码创建 Person 对象：

```javascript
// 基础原型
let personPrototype = {
  introduce: function() {
    return `Hi, I'm ${this.name}.`;
  }
};

// 构造函数
function Person(name) {
  let person = Object.create(personPrototype);
  person.name = name;
  return person;
}

// 创建实例
let ben = Person('Ben');
console.log(ben.introduce()); // 输出: Hi, I'm Ben.

let alice = Person('Alice');
console.log(alice.introduce()); // 输出: Hi, I'm Alice.
```

**攻击者利用原型污染**: 攻击者找到了某种方式，可以修改 `ben` 对象的原型上的 `introduce` 方法。最常见的方式是利用不安全的属性赋值操作，并使用 `__proto__` 作为键。

```javascript
// 攻击者的 Payload - 假设攻击者能控制对 ben 进行如下操作
ben.__proto__.introduce = function() {
  console.log("You've been hacked! The prototype is polluted.");
  // 或者注入恶意代码，如 <img src=x onerror=alert('XSS')>
  // this.isAdmin = true; // 甚至添加属性
};

// 验证污染效果
console.log(ben.introduce()); // 输出: You've been hacked! The prototype is polluted.

// !! 关键在于，其他实例也受到了影响 !!
console.log(alice.introduce()); // 输出: You've been hacked! The prototype is polluted.

// 未来创建的实例也会受影响
let charlie = Person('Charlie');
console.log(charlie.introduce()); // 输出: You've been hacked! The prototype is polluted.
```

**后台发生了什么**:

1.  `ben.__proto__` 指向 `personPrototype`。
2.  `ben.__proto__.introduce = ...` 直接修改了 `personPrototype` 对象上的 `introduce` 方法。
3.  由于 `alice` 和 `charlie` 的原型也是 `personPrototype`，当它们调用 `introduce` 方法时，它们会沿着原型链找到被污染的版本。

### 常见利用场景与函数 (Common Exploitation Scenarios and Functions)

原型污染漏洞通常发生在应用程序代码**不安全地处理用户提供的输入来修改对象属性**时。以下是一些需要特别关注的常见模式：

#### 1. 通过路径递归设置属性 (Setting Properties via Path Recursively)

*   **场景**: 函数根据一个路径字符串（如 `'a.b.c'` 或 `['a', 'b', 'c']`）来设置对象的嵌套属性，例如 `object[path[0]][path[1]][...] = value`。许多库（如 `lodash` 的 `_.set`）或自定义代码会实现此类功能。
*   **风险**: 如果路径的任何部分（特别是键名）可以被用户控制，并且没有对 `__proto__` 或 `constructor` 等特殊键进行过滤，攻击者就可以构造路径来污染原型。
*   **示例 (使用假设的 _.set 函数)**:
    ```javascript
    // 假设后端代码 (Node.js + lodash 或类似库)
    // let _ = require('lodash'); // 假设使用 lodash
    let friends = [ { id: 1, name: "testuser", reviews: [] } ];
    let targetFriend = friends[0]; // 找到要修改的对象

    // 假设 input 来自用户请求体: req.body = { path: '...', value: '...' }
    // 不安全的代码:
    // _.set(targetFriend, input.path, input.value);

    // 正常用户输入 (添加评论):
    // input = { path: 'reviews[0].content', value: 'Great profile!' }
    // 结果: targetFriend.reviews[0].content = 'Great profile!'

    // 攻击者输入 (试图污染 Object.prototype):
    // input = { path: '__proto__.polluted', value: true }
    // 如果 _.set 不安全:
    // targetFriend.__proto__.polluted = true;
    // 这会修改 targetFriend 的原型 (通常是 Object.prototype)
    // 导致所有普通对象 {} 都拥有了 polluted 属性
    let obj = {};
    console.log(obj.polluted); // 输出: true (如果污染成功)

    // 攻击者输入 (试图通过 constructor.prototype 污染):
    // input = { path: 'constructor.prototype.polluted', value: true }
    // 如果 _.set 不安全:
    // targetFriend.constructor.prototype.polluted = true;
    // 这也会修改 Object.prototype (因为 targetFriend.constructor 是 Object)
    console.log(obj.polluted); // 输出: true
    ```
*   **金色法则**:
    *   **`obj[x] = val`**: 如果攻击者能控制 `x` 并将其设为 `__proto__`，则可以在 `obj` 的原型上设置属性 `val`。
    *   **`obj[x][y] = val`**: 如果攻击者能控制 `x` 和 `y`，将 `x` 设为 `__proto__`，`y` 设为 `polluted_prop`，则可以在原型上设置 `polluted_prop = val`。
    *   **`obj[x][y][z] = val`**: 如果攻击者能控制 `x`, `y`, `z`，将 `x` 设为 `constructor`，`y` 设为 `prototype`，`z` 设为 `polluted_prop`，则可以在 `obj` 的构造函数的原型（通常是 `Object.prototype`）上设置 `polluted_prop = val`。这种方式更复杂，需要更深的对象结构。

#### 2. 对象递归合并 (Recursive Object Merging)

*   **场景**: 函数将一个源对象的属性递归地合并到目标对象中。常见于处理配置、更新设置等场景。
*   **风险**: 如果合并函数没有检查源对象中的键是否为 `__proto__`，并且直接将源对象的属性复制到目标对象（或其嵌套对象）上，攻击者可以通过提供一个包含 `__proto__` 键的恶意源对象来污染目标对象（及其原型链上的对象）。
*   **示例**:
    ```javascript
    // 易受攻击的递归合并函数
    function recursiveMerge(target, source) {
      for (let key in source) {
        // !! 关键缺陷：没有检查 key === '__proto__' !!
        if (source.hasOwnProperty(key)) { // hasOwnProperty 不能防止原型污染
          if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
            if (!target[key] || typeof target[key] !== 'object') {
              target[key] = {};
            }
            recursiveMerge(target[key], source[key]);
          } else {
            target[key] = source[key];
          }
        }
      }
    }

    // 假设的后端代码 (Node.js)
    let globalUserSettings = { theme: 'light' };

    // app.post('/updateSettings', (req, res) => {
    //   const userSettings = req.body; // 用户控制的输入
    //   recursiveMerge(globalUserSettings, userSettings); // 不安全的合并
    //   res.send('Settings updated!');
    // });

    // 攻击者发送的请求体:
    // { "__proto__": { "isAdmin": true } }

    // 执行 recursiveMerge(globalUserSettings, attackerInput);
    // 这会导致 globalUserSettings.__proto__.isAdmin = true;
    // 即 Object.prototype.isAdmin = true;

    // 验证污染
    let obj = {};
    console.log(obj.isAdmin); // 输出: true
    ```

#### 3. 对象克隆 (Object Cloning)

*   **场景**: 函数用于创建对象的副本。
*   **风险**: 如果克隆函数不安全，可能会意外地从源对象的原型链复制属性到新对象上，或者在克隆过程中允许通过特殊键（如 `__proto__`）进行污染。与递归合并类似，需要检查克隆逻辑是否会处理或过滤特殊属性。

### 原型污染的后果 (Consequences of Prototype Pollution)

原型污染的影响范围广泛，可能导致：

1.  **任意属性注入**: 攻击者可以在所有对象上添加或修改属性。这可能：
    *   **绕过访问控制**: 例如，添加 `isAdmin: true` 属性，如果后续代码仅检查 `if (user.isAdmin)`，则可能获得管理员权限。
    *   **覆盖关键逻辑**: 修改应用程序依赖的属性值。
2.  **任意代码执行 (通过 XSS)**:
    *   **客户端 (浏览器)**: 如果污染发生在前端 JavaScript 中，攻击者可以污染 DOM 元素的属性（如 `innerHTML`, `src`, `onerror`）或 JavaScript 内置对象的函数（如 `Object.prototype.toString`），从而注入可执行的脚本，导致 XSS。例如，污染 `element.__proto__.innerHTML = "<img src=x onerror=alert('XSS')>"`。
    *   **服务器端 (Node.js)**: 如果污染发生在后端，并且被污染的属性或方法被用于模板引擎渲染、命令执行、文件系统操作或其他敏感操作的参数中，可能导致服务器端代码执行 (RCE) 或其他严重后果。
3.  **拒绝服务 (Denial of Service - DoS)**:
    *   攻击者可以修改常用内置方法（如 `Object.prototype.toString`, `Object.prototype.hasOwnProperty`）的行为，使其抛出异常、进入无限循环或执行非常耗资源的操作。
    *   由于这些方法在 JavaScript 代码中被广泛隐式或显式调用，污染它们可能导致应用程序频繁出错、性能急剧下降甚至完全崩溃，拒绝为合法用户提供服务。
    *   **示例**:
        ```javascript
        // 攻击者污染 toString
        Object.prototype.toString = function() {
          console.error("DoS attempt via toString!");
          while(true) {} // 无限循环
          // 或者 throw new Error("Polluted toString!");
        };

        // 应用程序中任何地方隐式或显式调用 toString() 都可能触发 DoS
        let obj = {};
        console.log("User data: " + obj); // 隐式调用 obj.toString() -> 触发 DoS
        ```

### 检测与自动化 (Detection and Automation)

识别原型污染可能很棘手，因为它通常涉及对代码逻辑和数据流的深入理解。自动化工具可以提供帮助，但不能完全取代手动代码审计和测试。

*   **主要挑战**:
    *   漏洞点可能隐藏在复杂的代码逻辑或第三方库中。
    *   需要理解 JavaScript 的动态特性和原型继承。
    *   不像 SQL 注入或 XSS 那样有非常明确的模式，污染可能通过多种方式发生。
*   **手动审计关注点**:
    *   寻找任何使用**用户可控输入**来确定**对象键名**或**属性路径**的代码。
    *   检查执行**对象合并**、**克隆**或**属性设置**的函数，看它们是否对 `__proto__`, `constructor`, `prototype` 等特殊键进行了过滤或安全处理。
    *   分析第三方库的源代码或文档，了解它们处理对象操作的方式。
*   **自动化工具与资源**:
    *   **静态分析 (SAST)**:
        *   **NodeJsScan**: 针对 Node.js 应用的静态安全扫描器，包含对原型污染模式的检查。
        *   **ESLint 插件**: 可能有 ESLint 插件用于检测不安全的对象操作模式。
    *   **动态分析/模糊测试 (DAST/Fuzzing)**:
        *   **Prototype Pollution Scanner**: 扫描 JavaScript 代码以发现可能的污染模式。
        *   **PPFuzz**: 专门用于模糊测试 Web 应用以检测原型污染漏洞的工具。
        *   **Burp Suite 扩展**: 可能有扩展帮助检测或利用原型污染。
    *   **客户端检测**:
        *   **BlackFan's Client-Side Detection**: 提供识别客户端 JavaScript 中原型污染的示例和资源。
    *   **依赖项扫描**: 工具如 `npm audit` 或 Snyk 可以检测已知存在原型污染漏洞的第三方库版本。

**核心检测思路**: 寻找用户输入可以影响对象属性赋值中“键”的部分，并检查是否存在过滤。

### 防御措施 (Mitigation)

1.  **输入验证与清理**:
    *   **禁止使用 `__proto__`**: 在任何允许用户提供键名的地方，严格禁止使用 `__proto__`, `constructor`, `prototype` 作为键。
    *   **使用 `Object.create(null)`**: 创建没有原型的对象（字典/哈希映射），这样它们就不会继承自 `Object.prototype`，从而免疫对 `Object.prototype` 的污染。适用于存储键值对数据。
    *   **JSON Schema 验证**: 对来自用户的 JSON 输入使用严格的模式验证，只允许预期的属性。
2.  **使用安全的 API/库**:
    *   选择已知能够防御原型污染的库来进行对象合并、克隆等操作，或者仔细审计使用的库。
    *   优先使用 `Map` 而不是普通对象 `{}` 来存储键值数据，因为 `Map` 不受原型污染影响。
3.  **冻结原型**: 使用 `Object.freeze(Object.prototype)` 可以阻止对 `Object.prototype` 的进一步修改。但这可能破坏依赖于修改原型的库，需要谨慎评估。
4.  **代码审计与安全测试**: 定期进行代码审计和渗透测试，特别关注处理用户输入和对象操作的部分。
5.  **保持依赖项更新**: 定期更新第三方库，以获取已知的原型污染漏洞修复。