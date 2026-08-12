# 直连代理 (Direct Proxy)

[![Xposed Repo](https://img.shields.io/badge/Xposed%20Repo-available-blue?style=flat-square)](https://github.com/Xposed-Modules-Repo/org.xiyu.githubdirect)
[![Release](https://img.shields.io/github/v/release/FxxkLocation/Github-direct?style=flat-square)](https://github.com/FxxkLocation/Github-direct/releases)
[![Stars](https://img.shields.io/github/stars/FxxkLocation/Github-direct?style=flat-square)](https://github.com/FxxkLocation/Github-direct/stargazers)
[![Forks](https://img.shields.io/github/forks/FxxkLocation/Github-direct?style=flat-square)](https://github.com/FxxkLocation/Github-direct/network/members)
[![Issues](https://img.shields.io/github/issues/FxxkLocation/Github-direct?style=flat-square)](https://github.com/FxxkLocation/Github-direct/issues)
[![Size](https://img.shields.io/badge/Size-~80KB-brightgreen?style=flat-square)](#)
[![Telegram](https://img.shields.io/badge/Telegram-加入群组-blue?style=flat-square&logo=telegram)](https://t.me/+BUfEUGzViTg2YWU1)

**直连代理** 是一款 Android 平台**多平台规则驱动的直连框架**（原 GitHub Direct 项目演进而来）：通过 DNS 防污染 + 真实 IP 直连 + TCP 透明中继 + TLS ClientHello 分片，在免 Root 的 VPN 模式与 Root 的 Xposed 模式下修复大陆网络环境下对境外服务的访问。

- **0 运行时依赖**：无 Compose / Material / OkHttp，原生 XML + Vector Drawable，Release APK 约 **80 KB**（R8 高强度裁剪 + 资源压缩；体积大头是 60 平台的规则目录 profiles.json，UI 层仅数 KB）。
- **两种模式**：免 Root 的 `VpnService` 全机代理；已 Root 的 LibXposed 模块按作用域注入 DNS 修复。

---

## 重要澄清（能力边界）

> 原 README 声称 Xposed 模式会「动态修改 SNI 与 Host Header」——**这是错误的，特此修正**：

1. **Xposed 模式只修复 DNS**：模块仅 hook `InetAddress.getAllByName / getByName`（见 `ModuleMain.java`），对命中规则的域名返回真实 IP 列表（经 DoH 解析 + CIDR 过滤），对屏蔽域返回空数组 / 抛 `UnknownHostException`。**不修改、不伪造任何 TLS SNI 或 HTTP Host Header**，数据面全部是标准 TLS，走系统协议栈。
2. **SNI 相关绕过能力只存在于 VPN 模式**：TCP relay 层对首个 TLS ClientHello 做 **record 层分片**（`core/net/TlsFragmenter.kt`：在 SNI 域名字符串前 3 字节处把一个 TLS record 拆成两个独立 record，间隔 200ms 发送），使 DPI 无法从单个 TLS 记录中提取完整 SNI，从而绕过 SNI 阻断。
3. 因此，Xposed 模式能修复的是 **DNS 污染 / 解析被劫持** 类问题；**SNI 阻断** 类问题请在已 Root 设备上使用 VPN 模式，或在未 Root 设备上使用本应用的 VPN 模式。

---

## 平台覆盖

服务规则按 `verifyStatus` 分为四档（`assets/rules/profiles.json`，共 60 个 profile）：

| 档位 | 说明 |
| --- | --- |
| **Tier 1** | 已验证且**默认启用**：GitHub（回归基线） |
| **Tier 2** | 已验证、默认关闭：其余 54 个平台，可直接在「服务管理」中开启 |
| **Tier 3** | **NEEDS_VERIFY**（待验证）、默认关闭：5 个平台，规则已填充但真实直连可达性未经实测，开启前建议先跑「连通性诊断」 |
| **Tier 4** | **无 MITM 约束下不支持的能力**（架构 §12）：见下方列表，任何模式下均不提供 |

策略说明：

- **relay+frag**：`TLS_FRAGMENT_RELAY` — DoH 解析真实 IP → 虚拟 IP（vIP）应答 → TCP relay 转发 + ClientHello 分片（SNI 阻断域的完整方案）
- **clean-dns**：`CLEAN_DNS` — 仅 DoH 解析 + CIDR 过滤后返回真实 IP 直连，不 relay（IP 可直连的静态资源/CDN 域）
- **direct-ip**：`DIRECT_IP` — 固定 IP 直连（不解析）
- **nxdomain**：`NXDOMAIN` — 屏蔽域（返回 NXDOMAIN；同优先级下 block 支配 allow）
- resolver 策略：`DOH`（默认）／`PROVIDER_FIRST`（先查 hosts 表，miss 再 DoH；仅 GitHub 使用）

### Tier 1 — 默认启用

| 服务 | ID | 状态 | 策略 | 备注 |
| --- | --- | --- | --- | --- |
| GitHub 直连 | github | 已验证 | relay+frag + clean-dns | 14 条规则；核心域（github.com/api/gist 等）走 vIP + TLS 分片，静态资源 CDN 走 clean-dns；resolver=PROVIDER_FIRST（gitee hosts 源 + TCP 探活），默认启用 |

### Tier 2 — 已验证，默认关闭

| 服务 | ID | 策略 | 服务 | ID | 策略 |
| --- | --- | --- | --- | --- | --- |
| Google LLC | google-llc | relay+frag | Steam Store | steam-store | relay+frag |
| Telegram | telegram | relay+frag | Dropbox | dropbox | relay+frag |
| Discord | discord | relay+frag | MEGA | mega | relay+frag |
| Reddit | reddit | relay+frag+direct-ip | OneDrive Live | onedrive-live | relay+frag |
| Instagram | instagram | relay+frag | E-Hentai | e-hentai | relay+frag |
| Facebook | facebook | relay+frag | Nyaa | nyaa | relay+frag |
| Twitch | twitch | relay+frag | Pixiv | pixiv | clean-dns+nxdomain |
| Wikimedia Foundation | wikimedia | relay+frag | pixivFANBOX | pixiv-fanbox | clean-dns+nxdomain |
| Steam Community | steam-community | relay+frag | Dailymotion | dailymotion | relay+frag |
| DuckDuckGo | duckduckgo | relay+frag | V2EX | v2ex | clean-dns |
| Etsy | etsy | relay+frag | F-Droid | f-droid | relay+frag |
| Pinterest | pinterest | relay+frag | Proton | proton | relay+frag |
| Imgur | imgur | relay+frag | Gravatar | gravatar | relay+frag |
| BBC | bbc | relay+frag | Flickr | flickr | relay+frag |
| The New York Times | nytimes | relay+frag | Patreon | patreon | relay+frag |
| Quora | quora | relay+frag | Hugging Face | hugging-face | relay+frag |
| OK | ok | relay+frag | RFI | rfi | relay+frag |
| Rumble | rumble | relay+frag | Rutube | rutube | relay+frag |
| Vercel | vercel | relay+frag | Tails | tails | relay+frag |
| TheTVDB | thetvdb | relay+frag | Docker Hub | docker-hub | clean-dns |
| Prismic Images | prismic-images | relay+frag | WhatsApp | whatsapp | relay+frag |
| Amazon Japan | amazon-japan | relay+frag | APKMirror | apkmirror | clean-dns |
| OKX.COM | okx | clean-dns | X/Twitter | x-twitter | relay+frag |
| Archive of Our Own | ao3 | clean-dns | Greasy Fork | greasy-fork | clean-dns |
| Gelbooru | gelbooru | clean-dns+nxdomain | Wallhaven | wallhaven | clean-dns |
| Sankaku Complex | sankaku | clean-dns | Rule34Video | rule34video | clean-dns |
| Iwara | iwara | clean-dns | DLsite | dlsite | clean-dns |

### Tier 3 — NEEDS_VERIFY，默认关闭（开启前请先诊断）

| 服务 | ID | 策略 | 说明 |
| --- | --- | --- | --- |
| YouTube | youtube | relay+frag + clean-dns | 9 域 DoH 验证通过；googlevideo.com 按架构 §12.1 用 clean-dns（不做 gvt1 域重写），真实直连可达性需实测 |
| Z-Library | z-library | relay+frag | 镜像域名多、易漂移 |
| Audiomack | audiomack | clean-dns | 未实测 |
| Pornhub | pornhub | relay+frag | 未实测 |
| WGCZ Holding | wgcz-holding | clean-dns | 未实测 |

### Tier 4 — 无 MITM 约束下不支持的能力

本框架**不做 HTTPS 解密/注入（无 MITM）**，以下能力因此**明确不支持**（架构 §12）：

- **SNI 伪装 / SNI 改写**（把请求域名的 SNI 换成其它域名）
- **无 SNI 上游**（向不要求 SNI 的中间层转发 TLS）
- **CORS / CSP 改写**（修改响应头）
- **XFF / 来源 IP 伪造**（修改 HTTP 层头字段）
- **HTTP Host Header 改写**（数据面不触碰明文 HTTP）
- **UDP / QUIC 中继**（VPN 仅中继 TCP 与 DNS 查询）

需要这些能力的场景不在本框架的设计目标内。

---

## 技术细节

### 规则引擎（core/rules）

- 匹配器两种：**EXACT**（HashMap，O(1)）与 **SUFFIX**（反向 label trie，O(L)，L = 域名 label 数；前导点保证标签边界，`evilgithub.com` 不会命中 `.github.com`）
- 索引编译后只读，`match` 全程无锁，并发读安全
- 多规则命中仲裁：priority 高者胜 → 同 priority 下 NXDOMAIN（block）支配其它 transport → 仍并列取 serviceId 字典序小者（稳定）
- PASSTHROUGH 规则等于未命中；`enabled` 状态经 SettingsStore 惰性缓存（volatile），`setEnabled` 只写缓存并通知监听器，不改规则表

### 虚拟 IP 池（core/net/VirtualIpPool）

- `10.0.0.0/24`，主机位 10..254 共 **245 个** vIP
- **同域复用同 vIP**（客户端 DNS 缓存期内永远有效）；分配前必先取得真实 IP（vIP 绝不裸发）
- **LRU 驱逐**：仅驱逐 `refs == 0`（无活跃会话）的映射，被驱逐者进入墓地（graveyard，TTL 300s），TTL 内同域可复用原 vIP；全被租约钉住时返回池满（SERVFAIL）
- 租约：TcpRelay 会话建立 `lease(vIP)`、关闭 `release(vIP)`，与 TUN 会话生命周期绑定

### IPv6 策略

- 命中域且 `aaaaSuppress` 时，AAAA 查询应答 **NOERROR/NODATA**（名字存在，只是没有 AAAA），**绝不 NXDOMAIN**
- relay 域的 AAAA 同样 NODATA（仅 v4 中继），保证客户端 DNS 缓存语义正确

### QUIC 策略

- VPN 不中继 UDP（仅处理 DNS UDP:53），relay 域对 QUIC（UDP/443）**不分配 vIP** → 客户端自动回退 TCP
- 回退后的 TLS 流量走 TLS 分片中继兜底，QUIC 三态（直连可用/半死/失效）由该回退路径覆盖

### hosts feed（降级为可选优化）

- gitee `github-hosts` 源仅为 **github profile 的 provider 配置**（`providers` 声明），不是系统基础设施；仅在 VPN 模式启动，且只在 github profile 启用时同步
- 数据经 **TCP 探活**（443 端口，4s 超时）验证后才写入 RelayIpTable（copy-on-write）；探活失败/miss 自动回退 DoH（handler 链保证）；Xposed 进程不启动同步（表为空时自然走 DoH）
- 其它 profile 不依赖 hosts 表，移除该源不影响任何规则生效

### 内置诊断（仅网络元数据）

- **DNS 诊断**：对已启用 profile 的 testEndpoints 逐项输出「域名 → 命中服务 → transport 策略 → DoH A/AAAA 结果 → 状态/耗时」
- **连通性诊断**：`InetAddress.getByName` + `isReachable`（3s 超时），输出「域名 → 命中服务 → 策略 → 解析 IP/DNS 耗时 → TCP 状态/耗时」
- 只输出 DNS/TCP 元数据，**不发起任何 HTTP 请求、不输出 cookie/token/页面内容**；「引擎诊断日志」开关控制引擎侧日志（默认关闭 = 零日志开销）

---

## 使用方法

### 模式一：免 Root VPN 代理模式

1. 安装并打开本应用。
2. 首页点击「开启代理」，系统弹出 VPN 授权时选择允许。
3. 状态变绿后即可访问；「服务管理」中可开关各平台规则（默认仅 GitHub）。
4. 使用完毕点击「关闭代理」。

### 模式二：Xposed 框架模块模式（仅 DNS 修复）

1. 已 Root 设备安装 LSPosed（或支持 LibXposed 的框架）。
2. 在框架中启用本模块，作用域勾选需要修复访问的应用。
3. 强行停止目标应用或重启系统。
4. 打开本应用查看「模块状态」是否已激活。

> 注意：Xposed 模式只修复 DNS 污染（见「重要澄清」），SNI 阻断请在 VPN 模式下使用。

---

## 构建与测试

- 环境：JDK 21、Android SDK（compileSdk 36 / minSdk 26 / targetSdk 36）
- 构建：`./gradlew.bat assembleDebug`（Release：`assembleRelease`，R8 minify + shrinkResources）
- 测试：`./gradlew.bat test`（core 层纯 JVM 单测：规则引擎 / DoH / vIP 池 / TLS 分片 / DNS 编解码 / 拦截器，96 个用例全绿）
- 全部构建门：`./gradlew.bat assembleDebug test --no-daemon`

---

## 作者与交流

- **Created by**: Mai_xiyu
- **GitHub Repository**: [FxxkLocation/Github-direct](https://github.com/FxxkLocation/Github-direct)

如果您遇到任何使用上的问题、或有提供干净 IP / 新增平台的建议，欢迎提交 Issue，或加入我们的 Telegram 讨论群：

[加入 Telegram 群组](https://t.me/+BUfEUGzViTg2YWU1)

喜欢这个项目的话，别忘了点击上方的 **Star** 支持一下！
