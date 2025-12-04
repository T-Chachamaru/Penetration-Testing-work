#### 概述
CDN (Content Delivery Network) 通过在全球部署节点服务器，缓存网站内容，并将用户请求导向最近的节点，从而加速用户访问、分担源站压力。同时，CDN 服务通常会隐藏服务器的真实 IP 地址，并可能集成 WAF 功能，增加了一层安全防护。绕过 CDN 的主要目标是找到隐藏在 CDN 后面的 **源站真实 IP 地址**，以便直接对其进行渗透测试或攻击，绕开 CDN 的防护和加速层。

#### CDN 识别 (Identifying CDN Usage)
判断目标网站是否使用了 CDN 的常用方法：

1.  **多地 Ping 测试**：
    *   使用在线工具从全球不同地点 Ping 目标域名。
    *   **工具示例**：
        *   全球 Ping 测试：`https://wepcc.com`
        *   多个地点 Ping 服务器：`http://ping.chinaz.com` (站长工具 Ping)
        *   超级 Ping：`http://ping.aizhan.com` (爱站工具网)
    *   **判断依据**：
        *   **是 CDN**：返回多个 IP 地址，且这些 IP 地址分布在**不同地理区域**或属于**不同的运营商/云服务商**。
        *   **可能不是 CDN (或只是负载均衡)**：返回少数几个 IP 地址，且这些 IP 位于**同一地理区域**的不同运营商（可能是多线接入或负载均衡），或者只返回一个 IP。

#### 源站 IP 验证 (Verifying Origin IP)
找到疑似源站 IP 后，需要验证其真实性：

1.  **直接 IP 访问**：
    *   尝试直接使用 IP 地址（HTTP 或 HTTPS）访问网站。
    *   比较 IP 访问返回的页面内容、证书信息是否与通过域名访问时一致。
2.  **端口扫描与确认**：
    *   如果通过其他方法（如 C 段扫描）获得了一批可能的 IP，可以使用 Nmap 等工具扫描这些 IP 的常见 Web 端口（80, 443, 8080 等）。
    *   逐个访问开放了 Web 端口的 IP，确认哪个 IP 返回的是目标站点的内容。

#### CDN 绕过方法 (Bypass Techniques)

1.  **查询 DNS 历史记录**
    *   **原理**：查找域名在启用 CDN 服务之前的 DNS 解析记录，这些记录可能直接指向源站 IP。
    *   **工具/平台**：
        *   DNSDB: `https://dnsdb.io/zh-cn/`
        *   微步在线 (Threatbook): `https://x.threatbook.cn/`
        *   Netcraft Site Report: `http://toolbar.netcraft.com/site_report?url=` (查看历史 IP 变化)
        *   ViewDNS.info: `http://viewdns.info/` (提供 IP History 等多种查询)
        *   SecurityTrails: `https://securitytrails.com/` (提供详细的历史 DNS 数据)
            *   示例：访问 `https://securitytrails.com/domain/example.com/dns` 查看历史记录。
        *   IPip.net CDN 查询: `https://tools.ipip.net/cdn.php` (辅助判断)
    *   **MX 记录**：检查域名的 MX (邮件交换) 记录。如果邮件服务托管在与 Web 服务相同的服务器上，MX 记录可能暴露源站 IP。

2.  **查询子域名**
    *   **原理**：并非所有子域名都会配置 CDN，特别是那些非核心业务、内部使用或测试用的子域名（如 `dev.*`, `test.*`, `mail.*`, `vpn.*` 等）可能直接解析到源站 IP。
    *   **方法**：
        *   **在线平台**：微步在线 (`x.threatbook.cn`), DNSDB (`dnsdb.io`) 等。
        *   **搜索引擎**：Google Dorks (`site:example.com -www` 查找除 www 外的子域名)。
        *   **子域名扫描工具**：使用 Sublist3r, Amass, OneForAll 等工具进行爆破或利用公开资源查找。
        *   **网络空间搜索引擎**：Shodan, FOFA, Censys 等搜索域名或关联信息可能发现未受 CDN 保护的资产。

3.  **利用 SSL/TLS 证书**
    *   **原理**：SSL/TLS 证书通常包含颁发给的域名列表。通过查询证书聚合平台，可以找到使用相同证书的其他域名或 IP 地址，其中可能包含源站 IP。
    *   **工具**：Censys (`https://censys.io/`)
    *   **查询示例 (Censys)**：
        *   搜索证书：`parsed.names:example.com and tags.raw:trusted` (查找包含目标域名且受信任的证书)
        *   探索使用者：在证书详情页，点击 `Explore` -> `What's using this certificate?` -> `IPv4 Hosts` 查看使用该证书的 IP 地址。

4.  **利用 全球 DNS 查询差异**
    *   **原理**：部分 CDN 提供商可能只针对特定区域（如中国大陆）优化线路，并未覆盖全球。从国外或偏远地区的 DNS 服务器查询域名解析，可能直接返回源站 IP。
    *   **方法**：使用位于国外的 VPS 或在线 DNS 查询工具指定国外 DNS 服务器进行解析。

5.  **利用网站自身漏洞或信息泄露**
    *   **敏感文件泄露**：
        *   查找 `phpinfo()` 页面 (`phpinfo.php`, `test.php`, `info.php` 等)，其中可能包含服务器 IP 信息。
        *   查找探针文件、配置文件、日志文件等。
        *   检查 GitHub 等代码托管平台是否有源码泄露，可能包含硬编码的 IP 地址或配置信息。
    *   **服务端报错信息**：故意触发服务器错误（如提交畸形参数），有时错误页面会泄露服务器的内部 IP 地址或详细路径信息。
    *   **SSRF (Server-Side Request Forgery)**：利用 SSRF 漏洞让服务器向自身或其他内网地址发起请求，可以探测内网环境或获取服务器自身 IP。
    *   **XSS 盲打 / 命令执行**：
        *   通过 XSS 盲打平台接收来自后台的请求，其来源 IP 可能是源站 IP。
        *   利用命令执行漏洞执行 `curl ifconfig.me` 或反弹 Shell，获取源站 IP。
    *   **社工或获取管理员权限**：通过其他途径获取 CDN 管理后台的访问权限，可以直接查看配置中的源站 IP。

6.  **利用邮件订阅与服务**
    *   **邮件头信息**：订阅网站的邮件通知或 RSS Feed。查看收到的邮件**源码 (Header)**，特别是 `Received:` 字段，可能追踪到发送邮件服务器的 IP，该 IP 有时即为源站 IP。

7.  **特定负载均衡器指纹 (F5 LTM)**
    *   **原理**：当使用 F5 BIG-IP LTM 做负载均衡时，可能会在 Cookie 中插入包含编码后源站 IP 和端口的信息。
    *   **识别与解码**：
        *   查找形如 `Set-Cookie: BIGipServer<pool_name>=<encoded_ip>.<encoded_port>.0000` 的 Cookie。
        *   示例：`BIGipServerpool_8.29_8030=487098378.24095.0000`
        *   解码步骤：
            1.  取 IP 部分的十进制数：`487098378`。
            2.  转换为十六进制：`1d08880a`。
            3.  反转字节序（每两位一组）：`0a 88 08 1d`。
            4.  将每组十六进制转回十进制：`10.136.8.29`。此即为源站 IP。
            5.  端口部分 `24095` 转十六进制 `5e1f`，反转 `1f 5e`，转十进制 `8030`，即为源站端口。