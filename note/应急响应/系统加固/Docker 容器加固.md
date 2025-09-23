#### 1. 保护 Docker 守护进程 (Protecting the Docker Daemon)

如果攻击者能够与 Docker 守护进程 (Docker Daemon) 交互，他们就可以控制你系统上的所有容器和镜像。默认情况下，Docker 守护进程不暴露于网络，但手动暴露它是一种常见做法（尤其是在 CI/CD 等云环境中）。因此，必须通过以下方法对其进行保护。

##### 方法一：使用 SSH (Method 1: Using SSH)

通过 Docker 上下文 (contexts)，你可以安全地通过 SSH 与远程 Docker 守护进程交互。

1. **创建上下文**: 在你的客户端机器上，创建一个指向远程主机的 Docker 上下文。
    
    Bash
    
    ```
    docker context create \
    --docker host=ssh://myuser@remotehost \
    --description="Development Environment" \
    development-environment-host
    ```
    
2. **切换上下文**: 切换到新创建的上下文。此后，所有 `docker` 命令都将在远程主机上执行。
    
    Bash
    
    ```
    docker context use development-environment-host
    ```
    
3. **切换回默认**: 要管理本地 Docker 守护进程，可以切换回默认上下文。
    
    Bash
    
    ```
    docker context use default
    ```
    

##### 方法二：使用 TLS 加密 (Method 2: Using TLS Encryption)

你可以配置 Docker 守护进程，使其只接受通过 TLS 证书认证的客户端的连接。

- **启动服务器 (守护进程)**:
    
    Bash
    
    ```
    dockerd --tlsverify \
    --tlscacert=myca.pem \
    --tlscert=myserver-cert.pem \
    --tlskey=myserver-key.pem \
    -H=0.0.0.0:2376
    ```
    
- **连接客户端**:
    
    Bash
    
    ```
    docker --tlsverify \
    --tlscacert=myca.pem \
    --tlscert=client-cert.pem \
    --tlskey=client-key.pem \
    -H=SERVERIP:2376 info
    ```
    
- **参数说明**:
    
    - `--tlscacert`: 指定用于验证的证书颁发机构 (CA) 的证书。
        
    - `--tlscert`: 指定用于识别设备的证书。
        
    - `--tlskey`: 指定用于解密通信的私钥。
        

#### 2. 实施控制组 (cgroups) (Implementing Control Groups)

**控制组 (cgroups)** 是 Linux 内核的一项功能，用于限制和隔离进程的资源使用（CPU、内存等）。在 Docker 中使用 cgroups 可以防止有故障或恶意的容器耗尽整个主机的资源。

##### 限制容器资源 (Limiting Container Resources)

|资源|参数|示例命令|
|---|---|---|
|**CPU**|`--cpus="<cores>"`|`docker run -it --cpus="1.5" mycontainer`|
|**内存**|`--memory="<size>"`|`docker run -it --memory="512m" mycontainer`|

- **更新运行中的容器**:
    
    Bash
    
    ```
    docker update --memory="1g" mycontainer
    ```
    
- **查看资源限制**:
    
    Bash
    
    ```
    docker inspect mycontainer
    ```
    

#### 3. 防止特权容器 (Preventing Privileged Containers)

运行带有 `--privileged` 标志的容器极其危险，因为它会**完全移除**容器与主机之间的所有隔离机制，给予容器对主机的完全 root 访问权限，使其可以轻松“逃逸”。

##### Linux 能力 (Linux Capabilities)

作为 `--privileged` 的一个更安全的替代方案，**Linux 能力 (Capabilities)** 允许你以细粒度的方式为容器授予其真正需要的特定权限，而不是给予全部 root 权限。

|能力|描述|常见用例|
|---|---|---|
|`CAP_NET_BIND_SERVICE`|允许进程绑定到 1024 以下的端口。|允许 Web 服务器容器在无需 root 权限的情况下绑定到 80/443 端口。|
|`CAP_SYS_ADMIN`|授予多种管理权限，如挂载文件系统、修改网络设置等。|用于需要执行管理任务的自动化脚本容器。|
|`CAP_SYS_RESOURCE`|允许进程修改其资源限制。|用于需要动态调整自身资源消耗的性能敏感型应用。|

> **最佳实践**: **绝不**使用 `--privileged`。应使用 `--cap-add` 和 `--cap-drop` 来精确地为容器授予其完成任务所需的最小权限集。
> 
> Bash
> 
> ```
> # 为容器添加绑定低位端口的能力
> docker run -d --cap-add=NET_BIND_SERVICE my-web-server
> ```

#### 4. 高级隔离：Seccomp 与 AppArmor (Advanced Isolation: Seccomp & AppArmor)

##### Seccomp (安全计算模式)

Seccomp 是一个 Linux 内核安全功能，它通过一个配置文件来限制容器可以执行的**系统调用 (syscalls)**。这就像一个白名单，只允许容器执行其正常功能所必需的系统调用。

- 示例 Seccomp 配置文件 (profile.json):
    
    此配置文件允许文件读写，但禁止所有网络相关的系统调用（如 socket, connect）。
    
    JSON
    
    ```
    {
      "defaultAction": "SCMP_ACT_ALLOW",
      "architectures": ["SCMP_ARCH_X86_64"],
      "syscalls": [
        { "name": "socket", "action": "SCMP_ACT_ERRNO" },
        { "name": "connect", "action": "SCMP_ACT_ERRNO" },
        { "name": "bind", "action": "SCMP_ACT_ERRNO" }
      ]
    }
    ```
    
- **应用 Seccomp 配置文件**:
    
    Bash
    
    ```
    docker run --rm -it --security-opt seccomp=/path/to/profile.json mycontainer
    ```
    

##### AppArmor (应用程序盔甲)

AppArmor 是一个**强制访问控制 (MAC)** 系统，它通过一个配置文件来限制应用程序可以访问的**资源**（如文件路径、网络端口、Linux 能力）。

- **应用流程**:
    
    1. **创建 AppArmor 配置文件**: 编写一个定义允许和拒绝规则的文本文件。
        
    2. **加载配置文件到 AppArmor**:
        
        Bash
        
        ```
        sudo apparmor_parser -r -W /path/to/apparmor_profile
        ```
        
    3. **运行容器并应用配置文件**:
        
        Bash
        
        ```
        docker run --rm -it --security-opt apparmor=your_profile_name mycontainer
        ```
        

##### Seccomp vs. AppArmor：有什么区别？

- **AppArmor**: 关注**“应用程序可以访问什么”**（例如，它可以读写 `/var/log`，但不能读取 `/etc/passwd`）。
    
- **Seccomp**: 关注**“应用程序可以做什么”**（例如，它可以执行 `read` 和 `write` 系统调用，但不能执行 `socket` 系统调用）。
    

> **纵深防御**: 这两者不是互斥的。最佳安全实践是**同时使用** AppArmor 和自定义的 Seccomp 配置文件，为容器创建多层安全防护。