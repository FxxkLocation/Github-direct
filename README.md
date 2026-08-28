# GitHub-direct

GitHub-direct 是面向 Android Root/LSPosed 环境的选择性直连模块。它针对 DNS 污染、部分 IP 阻断及 TLS ClientHello 阶段干扰，将“可信候选 IP”与透明 TLS 中继组合起来。默认候选/分片路径不解密 HTTPS、不改写 SNI、证书或 HTTP 内容；对用户二次授权的浏览器 UID，可选启用每设备 CA + 严格 ECH 上游验证的本机 TLS 终止，以处理仅靠 ClientHello 分片仍失败的平台。

GitHub 全链路仍是已完成真机验证的基线：浏览器、HTTPS Git、API、Raw、静态资源与 Release 下载。Google、YouTube、Discord、OpenAI/ChatGPT 已接入同一可信候选、IPv6 与 TLS 数据面；Android 16 + Edge 上的 Discord Web、二维码登录 WebSocket 已通过，但对应原生客户端和其他平台尚未完成全链路验收，因此 profile 仍保持 `NEEDS_VERIFY`、默认关闭。

这里的“内置浏览器应用”不是指独立浏览器，而是 Electron-like 的宿主客户端。Electron 官方只支持 Windows、macOS 与 Linux；Android 上的对应形态通常是 WebView、Cronet、GeckoView、CEF/Crosswalk 或其他混合运行时。模块按实际宿主包/UID 工作，不按网页 renderer 名称工作；应用能接收网页 Intent 也不等于它使用了某一种内置运行时。

## 当前架构

- **现代 LSPosed 模块**：使用 libxposed API 102，`minApiVersion=101`。在 package-ready 阶段安装同步、缓存型 DNS Hook，在 `Application.attach` 获取宿主 Context 后初始化只读规则快照。
- **跨进程配置闭环**：模块应用通过 LSPosed Remote Preferences 单向发布服务开关、活动路由和随机心跳令牌；目标进程通过只接受 `record` 的 write-only Provider 回传心跳，Provider 同时校验 token、Binder 调用 UID、包名与进程名。Root/UID/hosts 原始数据不会复制到目标进程；远程配置暂不可用时 Hook 保护性放行。
- **明确的作用域**：LSPosed 作用域与 Root UID 作用域分别显示。平台客户端、Electron-like 宿主、独立浏览器及 Git 客户端都必须由用户明确加入；空 Root 作用域不会退化为“所有应用”。
- **Electron-like 宿主捕获**：可对 `SELECTED_APPS` 的二次授权子集捕获全部 IPv4 TCP/443。启用平台的可见 SNI 使用候选/分片；非目标 HTTPS 通过 `SO_ORIGINAL_DST` 原样透传。对应 UID 的 IPv4 QUIC 被 REJECT/DROP 以回退 TCP；IPv6 保持系统原生直连，避免破坏可用的流媒体双栈路径。
- **可信候选系统**：所有启用平台合并固定 IP Wire DoH、本机 DNS 观测及历史安全快照；GitHub 额外使用内置快照、官方 Meta 与不超过 7 天的社区 hosts 种子。候选必须通过合法性、TCP、严格 SNI、系统信任链和主机名验证。
- **候选与 TLS 终止分离**：普通直连/分片候选仍按精确目标发布；显式同 CDN 池只共享待测 IP，每个目标都重新执行系统信任链与主机名验证。可选 TLS 终止可对“已启用 profile 明确声明的一方后缀”发布受控 NO-SNI/ECH 路由：后缀先以固定代表子域验证边缘能力，真实连接再按实际 SNI 逐次验证；未知第三方后缀不能仅凭观测进入 CA 边界。
- **每设备浏览器 CA**：公开 CA 通过 Android 用户信任库存储并以 `AndroidCAStore` 复验；私钥只存在于应用私有目录，Root 所有、权限 `0600`，不会写入 APK、Root 模块或浏览器策略。Edge 138+ 被选入 TLS 捕获时，模块同时合并并复验 `CACertificates` / `CAPlatformIntegrationEnabled` 应用限制；同一 DER 不允许同时留在系统/APEX 与用户根库。
- **按网络隔离健康度**：每域最多 32 个候选，并发探测最多 4 个；记录延迟 EWMA、失败次数、退避与 `DIRECT_TLS` / `FRAGMENTED_TLS` / `UNUSABLE` 主能力，并独立记录同一 IP 是否通过严格 NO-SNI 验证。
- **Root 透明数据面**：对用户所选 UID 的已启用平台 IPv4/IPv6 目标拦截 TCP/443；UDP/443 优先 REJECT，不支持时 DROP，使 QUIC 回退到 TCP。SELECTED 作用域按 UID 生成入口、共享一次载荷链，规则规模为 O(U+R)；只有二次授权的 Electron-like 宿主增加一个 O(E) 全 TLS 兜底。IPv4 与 IPv6分别事务化安装并统一回滚。
- **真实目的地址恢复**：JNI 读取 `SO_ORIGINAL_DST`。原生库不可用时关闭真实 IP 重定向，不盲目接管连接。
- **TLS 中继**：最多缓存 64 KiB、1 秒的多-record ClientHello。先按虚拟 IP、白名单 SNI、唯一原 IP 分组路由；无法确认时原样连接原目的地址。
- **候选竞速**：第一候选未在 225 ms 内成功时竞速第二候选；仅在尚未向客户端返回服务器数据前重试。
- **故障开放**：真实 IP 的 ipset 元素使用约 20 秒租约、每 5 秒刷新；所有模式同时使用最小 Root 守护器，心跳失效后只清理本模块明确生成的 `GHD_*` 链，覆盖 DNS/vIP 重定向残留。
- **可观测性**：UI 显示服务状态、活动规则代次、Root UID、候选数、失败阶段，以及 Hook 初始化包、进程、时间、框架版本、配置代次和 Java DNS 命中数。Chromium 使用原生 DNS 时允许显示 `DNS 命中 0`，Root 数据面仍可正常工作。

## 兼容范围

| 项目 | 当前范围 |
| --- | --- |
| Android | 首期验收 Android 12–16；APK 的 `minSdk=26`、`targetSdk=36` |
| LSPosed | 现代 API 101+；编译 API 102 |
| Root | Magisk / KernelSU，需提供可用的 `su`、iptables；完整 ip6tables 能力启用 IPv6 接管；ipset 为可选加速 |
| ABI | arm64-v8a、armeabi-v7a、x86_64 |
| 原生页大小 | ELF LOAD 对齐 16 KiB |
| 数据面 | HTTPS/TCP 443；UDP/443 仅用于目标 QUIC 回退；Discord Voice UDP/3478 不在首期范围 |
| 可选 TLS 终止 | 仅用户二次授权的浏览器/宿主 UID；当前实机验证 Edge 151，证书锁定原生 App 不承诺兼容 |

真实 IP 防火墙同时支持 IPv4 与 IPv6：能力探测必须确认 `ip6tables` 的 nat/OUTPUT、owner、REDIRECT、save/restore 均可用，随后规则才会指向已实际绑定的 `::1` 中继；否则 UI 明确显示仅 IPv4，且不会安装可能形成黑洞的 IPv6 规则。GitHub 基线仍抑制 AAAA；Google、YouTube、Discord、OpenAI 保留真实 AAAA。设备没有 IPv6 NAT 能力时，这些平台的 IPv6 连接保持原生直连，可用于网络本身已可达的流媒体/长连接。SSH/22、UDP/QUIC 中继、ECH 下无法可靠归类的流量、任意公网扫描、外部代理和证书绕过均不在范围内。

### 与 Sheas Cealer 的关系

[Sheas Cealer Droid](https://github.com/SpaceTimee/Sheas-Cealer-Droid) 的公开说明是利用 Chromium 启动参数伪造 SNI。GitHub-direct 借鉴其“浏览器内 SNI 干扰可被针对性处理”的思路，但不写 Chromium 全局启动参数，也不关闭证书校验：Chromium 专用路径无法覆盖 Firefox、GitHub App 或 HTTPS Git，并可能扩大到同一浏览器的全部流量。

对浏览器与 Electron-like Android 宿主，当前安全路径是：按应用 UID 拦截目标 DNS/TCP 流量；对原生 DNS/Cronet 路径可显式启用全 TLS 捕获；优先使用严格证书验证通过的精确候选或真实 ClientHello 分片。只有用户另外开启 TLS 终止并完成每设备 CA/浏览器策略验证后，已启用规则中的一方域才会进入严格 NO-SNI 或目标原生 ECH 中继。

本实现不是“任意伪造 SNI + nginx 通配反代”：上游必须完成真实内层主机名、公开证书链和 ECH 验证，失败即关闭连接；CA 只覆盖用户选择的 UID 与平台后缀。证书锁定 App 仍可能失败，因此原生客户端默认继续使用不解密路径。

## 使用

1. 安装 APK，并在 LSPosed 中启用模块。
2. 在 LSPosed 中只勾选需要处理的平台客户端、宿主应用或浏览器，然后强行停止并重启目标应用。
3. 打开 GitHub-direct，授予 Root；在 Root 作用域中选择同一宿主包。对使用 Cronet/内置 Chromium 且普通 DNS 路径无法覆盖的客户端，再在“内置运行时全 TLS 捕获”中二次选择；不要对无关应用开启。
4. 在服务管理中按需启用 Google、YouTube、Discord 或 OpenAI。它们当前默认关闭并标记待验证。
5. 若确需浏览器 TLS 终止，先生成并安装每设备 CA，再开启该功能。Edge 138+ 被选中时模块会自动安装并复验浏览器 CA 策略；任一步不可信都会阻止 TLS 终止启动。
6. 如需开机恢复，手动开启“开机自动启动”；默认不自动启用。
7. 在状态页确认：
   - LSPosed 作用域与 Root UID 作用域符合预期；
   - Hook 心跳出现目标包名；Chromium 的 Java DNS 命中数可以为 0；
   - Root 服务、活动规则代次和候选数有效；
   - 若启用 TLS 终止，CA 显示 `TRUSTED`，本机 TLS 路由数大于 0；
   - 没有失败阶段或残留规则告警。

三个基础发布开关默认开启，可用于分阶段回滚；TLS 终止是独立、默认关闭的高边界开关：

- `adaptive_candidates`：候选刷新、探测与动态排序。
- `real_ip_redirect`：已启用平台的真实/污染 IP 重定向，以及显式宿主的全 TLS 捕获。
- `tls_fragment_v2`：多-record ClientHello 分片策略。
- `tls_termination`：每设备 CA + 严格 ECH 的浏览器 TLS 终止。

异常时先关闭 `tls_termination`，再按 `tls_fragment_v2` → `real_ip_redirect` → `adaptive_candidates` 的顺序回滚。

## 数据与安全边界

- 污染 DNS 地址只进入“需要拦截的目标集”，不会被提升为上游候选。
- GitHub Meta 的大网段只用于归属校验和防火墙范围，不进行地址扫描。
- TLS 探测使用系统信任链与主机名校验；无 TrustAll。
- CA 私钥不离开应用私有目录；APK 与 Edge 策略只包含公开证书。卸载操作按精确 DER 删除，不清理其他 CA 或应用限制。
- TLS 终止后缀必须来自已启用 profile 的显式标签边界；代表子域只用于发布前能力预检，实际 SNI 的上游公开证书或 ECH 任一验证失败都会关闭连接。第三方新域只记录/验证，不自动扩大解密范围。
- Hook 热路径只读不可变快照，异常保护性放行，不直接执行 DoH、网络探测或长等待。
- Hook 目标进程无权修改 Remote Preferences；心跳端点不支持读取、查询或任意键写入，并校验 128-bit token 与 Binder 调用 UID。
- 规则快照先写磁盘并暂存；仅当同代防火墙安装成功后才发布为 active generation。

## 构建与验证

需要 JDK 21、Android SDK Platform/Build Tools 37.0、NDK 28.2.13676358 和 CMake 3.22.1。

```bash
./gradlew testDebugUnitTest lintDebug verifyXposedReleaseApk --no-daemon
```

最低框架 API 兼容性可单独验证：

```bash
./gradlew compileDebugJavaWithJavac --init-script gradle/verify-libxposed-101.init.gradle --no-daemon
```

Windows 使用：

```powershell
.\gradlew.bat testDebugUnitTest lintDebug verifyXposedReleaseApk --no-daemon
```

`verifyXposedReleaseApk` 会构建 Release APK，并校验现代 Xposed 元数据、三个 JNI ABI、每个 ELF 的 16 KiB LOAD 对齐，以及 `zipalign -c -P 16`。

当前发现 404 项 JVM 测试：默认离线门禁执行通过 403 项，另 1 项真实公网 TLS 候选探测按设计跳过。可显式运行该探测：

```powershell
$env:GHD_LIVE_TLS_PROBE='1'
.\gradlew.bat testDebugUnitTest --tests '*TlsEndpointProbeLiveTest' --no-daemon
```

该测试验证直连/record 分片能力、系统信任链和主机名校验，不替代 Android/LSPosed/Root 真机矩阵。真机验收步骤与记录模板见 [docs/VALIDATION.md](docs/VALIDATION.md)。

构建产物：

- Debug：`app/build/outputs/apk/debug/app-debug.apk`
- Release：`app/build/outputs/apk/release/app-release.apk`

Release 当前使用 debug signing，仅用于开发验证；正式发布前必须切换到受控发布密钥。

## 项目

- Repository: https://github.com/FxxkLocation/Github-direct
- Xposed Repo: https://github.com/Xposed-Modules-Repo/org.xiyu.githubdirect
