#### 概述 (Overview)
Docker 是一个开源的应用容器引擎，允许开发者将应用及其依赖打包到一个轻量级、可移植的容器中，然后发布到任何流行的 Linux 或 Windows 机器上，也可以实现虚拟化。容器是完全使用沙箱机制，相互之间不会有任何接口，并且性能开销极低。它通过容器化技术简化了应用的部署、测试和分发流程，提高了资源利用率和环境一致性。

**核心概念**:
*   **镜像 (Image)**: 一个只读的模板，包含了运行容器所需的文件系统内容、库、依赖、环境变量和配置。镜像是创建容器的基础。
*   **容器 (Container)**: 镜像的可运行实例。容器与宿主机和其他容器隔离，拥有自己的文件系统、网络和进程空间。可以被创建、启动、停止、移动和删除。
*   **仓库 (Registry)**: 集中存储和分发 Docker 镜像的服务。最著名的是 Docker Hub (公共仓库)，也可以搭建私有仓库。
*   **Dockerfile**: 一个文本文件，包含了一系列指令，用于自动化地构建 Docker 镜像。

#### 安装与基本配置 (Installation & Basic Configuration)

*   **安装 (Installation)**
    *   **CentOS**: `yum install docker -y` (或按照 Docker 官方文档添加源安装最新版)
    *   **Kali/Debian/Ubuntu**: `apt update && apt install docker.io -y` (或按照 Docker 官方文档添加源安装最新版)
*   **服务管理 (Service Management)**
    *   启动 Docker 服务: `systemctl start docker`
    *   设置开机自启: `systemctl enable docker`
    *   查看 Docker 服务状态: `systemctl status docker`
*   **验证安装 (Verification)**
    *   查看 Docker 版本: `docker -v` 或 `docker version`
    *   运行 Hello World 测试: `docker run hello-world`
*   **镜像加速器 (Mirror Configuration - Optional but Recommended)**
    *   **目的**: 加快从 Docker Hub 拉取镜像的速度（尤其在中国大陆）。
    *   **配置**: 修改 Docker 配置文件（通常是 `/etc/docker/daemon.json`），添加 `registry-mirrors` 字段，指向国内镜像加速地址（如阿里云、网易云、USTC 等提供的地址），然后重启 Docker 服务。
    *   示例 (`/etc/docker/daemon.json`):
        ```json
        {
          "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn", "https://hub-mirror.c.163.com"]
        }
        ```

#### 镜像管理 (Image Management)

*   **概述**: 管理用于创建容器的镜像模板。
*   **常用命令**:
    *   `docker search <image_name>`: 在 Docker Hub (或配置的 Registry) 搜索镜像。
    *   `docker pull [<registry_host>/]<image_name>[:<tag>]`: 从 Registry 下载镜像。
        *   `<registry_host>`: 可选，指定仓库地址 (如 `docker.mirrors.ustc.edu.cn`)。
        *   `<image_name>`: 镜像名称 (如 `library/nginx` 或 `nginx`)。
        *   `<tag>`: 可选，镜像标签/版本 (如 `1.16`, `latest`)。默认为 `latest`。
        *   示例: `docker pull docker.mirrors.ustc.edu.cn/library/nginx:1.16`
    *   `docker images`: 列出本地已下载的所有镜像。
    *   `docker rmi <image_id_or_name>[:<tag>]`: 删除一个或多个本地镜像。需要先停止并删除使用该镜像的容器。
    *   `docker save -o <output_filename.tar> <image_name>[:<tag>]`: 将一个或多个本地镜像打包保存为 `.tar` 归档文件。
    *   `docker load -i <input_filename.tar>`: 从 `.tar` 归档文件加载镜像到本地。
    *   `docker tag <source_image>[:<tag>] <target_image>[:<tag>]`: 为本地镜像创建一个新的标签（别名），常用于推送前标记。
    *   `docker login [<registry_host>]`: 登录到 Docker Registry。
    *   `docker push [<registry_host>/]<image_name>[:<tag>]`: 将本地镜像上传到指定的 Registry (需要先登录并有相应权限)。

#### 容器管理 (Container Management)

*   **概述**: 创建、运行、监控和删除镜像的实例——容器。
*   **常用命令**:
    *   `docker run [OPTIONS] IMAGE [COMMAND] [ARG...]`: 基于指定镜像创建并启动一个新容器。
        *   **常用选项 (OPTIONS)**:
            *   `-d`: 后台运行容器 (Detached mode)。
            *   `-it`: 以交互模式运行容器，分配一个伪终端，通常用于进入容器 Shell (`-i`: interactive, `-t`: pseudo-TTY)。
            *   `-p <host_port>:<container_port>[/protocol]` 或 `-P`: 端口映射。`-p` 指定映射关系，`-P` 随机映射所有暴露的端口。
            *   `--name <container_name>`: 为容器指定一个易于识别的名称。
            *   `-v <host_path>:<container_path>[:ro]`: 卷挂载，将宿主机目录/文件挂载到容器内。`:ro` 表示只读。
            *   `-e <KEY>=<VALUE>`: 设置容器内的环境变量。
            *   `--link <container_name>:<alias>`: (旧方式，已被 Docker 网络取代) 连接到另一个容器，允许通过别名通信。
            *   `--network <network_name>`: 将容器连接到指定的 Docker 网络。
            *   `--rm`: 容器退出时自动将其删除。
        *   **示例**:
            *   `docker run -d -p 80:80 --name mynginx nginx:latest` (后台运行 Nginx，映射 80 端口)
            *   `docker run --name mysql_db -e MYSQL_ROOT_PASSWORD=123456 -d mysql:5.7` (后台运行 MySQL，设置 root 密码)
            *   `docker run -d --name mywp --link mysql_db:mysql -p 85:80 wordpress:5.6` (运行 WordPress，连接 MySQL 容器，映射 85 端口)
    *   `docker ps`: 列出当前正在运行的容器。
        *   `docker ps -a`: 列出所有容器（包括已停止的）。
    *   `docker stop <container_id_or_name> [<container_id_or_name>...]`: 停止一个或多个运行中的容器。
    *   `docker start <container_id_or_name> [<container_id_or_name>...]`: 启动一个或多个已停止的容器。
    *   `docker restart <container_id_or_name> [<container_id_or_name>...]`: 重启一个或多个容器。
    *   `docker rm <container_id_or_name> [<container_id_or_name>...]`: 删除一个或多个已停止的容器。
        *   `docker rm -f <container_id_or_name>`: 强制删除容器（即使正在运行）。
    *   `docker exec -it <container_id_or_name> <command>`: 在运行中的容器内执行命令。
        *   示例 (进入容器 Shell): `docker exec -it mynginx /bin/bash` (或 `/bin/sh`)。
    *   `docker logs [-f] <container_id_or_name>`: 查看容器的标准输出和标准错误日志。`-f` 实时跟踪。
    *   `docker top <container_id_or_name>`: 显示容器内运行的进程。
    *   `docker stats [<container_id_or_name>...]`: 实时显示一个或多个容器的资源使用统计 (CPU, Mem, Net I/O, Block I/O)。
    *   `docker inspect <container_id_or_name>`: 显示容器或镜像的详细底层信息 (JSON 格式)。

#### 创建自定义镜像 (Creating Custom Images)

*   **概述**: 将包含特定应用、配置或修改的容器状态保存为新的镜像，以便部署和分发。

*   **方法 1: 使用 `docker commit` (不推荐用于自动化和生产)**
    *   **原理**: 基于现有容器的当前状态创建一个新镜像。
    *   **步骤**:
        1.  启动一个基础容器并进入: `docker run -it --name temp_container debian:latest /bin/bash`
        2.  在容器内安装软件、修改配置: `apt update && apt install -y nginx && ...`
        3.  退出容器 (`exit`)。
        4.  提交更改为新镜像: `docker commit temp_container <new_image_name>:<tag>` (如 `my-debian-nginx:v1`)。
    *   **缺点**: 过程不透明、不可追溯，可能包含构建缓存和临时文件，镜像层较大。

*   **方法 2: 使用 Dockerfile (推荐)**
    *   **原理**: 编写一个包含指令的 `Dockerfile` 文本文件，描述构建镜像的步骤。Docker 根据此文件自动构建镜像。
    *   **优点**: 构建过程透明、可重复、版本化、易于维护，镜像层次更优化。
    *   **基本结构**:
        ```dockerfile
        # 指定基础镜像
        FROM debian:latest
        # 设置维护者信息 (可选)
        LABEL maintainer="Your Name <your.email@example.com>"
        # 更新源并安装软件
        RUN apt-get update && apt-get install -y nginx \
            && rm -rf /var/lib/apt/lists/*
        # 复制文件 (可选)
        # COPY ./my-config.conf /etc/nginx/nginx.conf
        # 暴露端口 (可选)
        EXPOSE 80
        # 定义容器启动时执行的命令
        CMD ["nginx", "-g", "daemon off;"]
        ```
    *   **构建命令**: 在包含 `Dockerfile` 的目录下执行 `docker build -t <image_name>:<tag> .` (如 `docker build -t my-debian-nginx:v2 .`)。

#### Docker Compose

*   **概述**: 用于定义和管理多容器 Docker 应用的工具。通过一个 YAML 文件 (`docker-compose.yml`) 配置应用的服务、网络、卷等，实现一键启动、停止整个应用栈。
*   **安装**: 通常需要单独安装 (参考 Docker 官方文档)。
*   **核心文件**: `docker-compose.yml` (定义服务、网络、卷等)。
*   **常用命令**: (在包含 `docker-compose.yml` 的目录下执行)
    *   `docker-compose up [-d] [--build]`: 创建并启动所有服务。`-d` 后台运行。`--build` 在启动前强制重新构建镜像。
    *   `docker-compose down [-v]`: 停止并删除所有服务相关的容器、网络。`-v` 同时删除数据卷。
    *   `docker-compose stop [service_name...]`: 停止指定服务（或所有服务）的容器。
    *   `docker-compose start [service_name...]`: 启动已停止的服务容器。
    *   `docker-compose restart [service_name...]`: 重启服务容器。
    *   `docker-compose ps`: 列出 Compose 项目中的容器状态。
    *   `docker-compose logs [-f] [service_name...]`: 查看服务日志。
    *   `docker-compose exec <service_name> <command>`: 在指定服务的容器内执行命令。
    *   `docker-compose build [service_name...]`: 构建或重新构建服务镜像。
    *   `docker-compose pull [service_name...]`: 拉取服务所需的镜像。
    *   `docker-compose config`: 验证并查看 Compose 文件配置。

#### 应用示例：Vulhub 靶场环境 (Application Example: Vulhub)

*   **概述**: Vulhub 是一个基于 Docker 和 Docker Compose 的开源漏洞测试/复现环境集合，提供大量预配置好的漏洞场景。
*   **使用步骤**:
    1.  **获取 Vulhub**: `git clone https://github.com/vulhub/vulhub.git`
    2.  **选择漏洞环境**: `cd vulhub/<category>/<vulnerability_directory>` (如 `cd vulhub/struts2/s2-045`)
    3.  **启动靶场**: `docker-compose up -d`
    4.  **访问与测试**: 根据该漏洞目录下的 `README.md` 文件提供的访问地址和说明进行漏洞复现。
    5.  **关闭并清理环境**: `docker-compose down [-v]`