# GitHub-direct 验收矩阵

本文区分“自动化验证已通过”和“必须在真实设备执行”的项目。未连接对应设备时，不得把真机项标记为通过。

## 自动化门禁

```bash
./gradlew testDebugUnitTest lintDebug verifyXposedReleaseApk --no-daemon
```

门禁必须同时满足：

- 当前发现 404 项 JVM 测试：默认离线门禁 403 项通过，1 项 opt-in 公网 TLS 探测按设计跳过。
- SELECTED 作用域使用每 UID 入口与单一共享载荷链；100 个 UID 的回归样本仍只能生成 245 条 vIP REDIRECT 载荷规则。
- Electron-like 宿主的全 TLS 捕获只能是 SELECTED scope 的显式子集；目标链必须先于全捕获兜底，非 scope UID 与关闭 `real_ip_redirect` 时不得生成该规则。
- 普通直连/分片候选只按完成 TLS 主机名验证的精确目标发布。同 CDN 池只共享待测 IP，目标必须独立复验。可选 TLS 终止仅能在已启用 profile 的显式一方后缀内发布：NO-SNI 后缀需通过代表子域的系统链/主机名与本机端到端验证，ECH 使用目标自身 HTTPS RR；每个实际 SNI 仍由上游严格复验并 fail-close。
- Android Lint 0 error。
- Release APK 包含准确的 `META-INF/xposed/java_init.list`、`module.prop`、`scope.list`，且使用 LF。
- 三个 ABI 均包含 `libghdnet.so`。
- `zipalign -c -P 16 -v 4 app-release.apk` 通过。
- 三个原生库的 ELF LOAD alignment 均不小于 `0x4000`。
- `git diff --check` 无错误。
- GitHub Actions 外部依赖全部固定到 40 位 commit SHA；Dependabot 负责提出更新。

可选的真实公网候选探测需显式开启：

```powershell
$env:GHD_LIVE_TLS_PROBE='1'
.\gradlew.bat testDebugUnitTest --tests '*TlsEndpointProbeLiveTest' --no-daemon
```

它验证系统信任链、主机名和直连/record 分片能力，不替代下面的 Android 真机矩阵。

## 设备矩阵

| 编号 | Android | Root | 主要网络 | 必测应用 | 状态 |
| --- | --- | --- | --- | --- | --- |
| A | 12 / API 31 | Magisk | 双栈 Wi-Fi | GitHub App、Chrome | 未执行 |
| B | 14 / API 34 | KernelSU | 双栈蜂窝 | GitHub App、Firefox | 未执行 |
| C | 16 / API 36 | Magisk 或 KernelSU | 双栈 Wi-Fi + 蜂窝切换 | Edge、Android WebView/Cronet 宿主 | 部分通过：KernelSU / Edge / IPv4 Wi-Fi |
| D | 12–16 | Magisk 或 KernelSU | 双栈 Wi-Fi | Google、YouTube、Discord、OpenAI 客户端 | 部分通过：Android 16 / Edge / Discord Web |

### 已执行记录：C-KSU-EDGE-WIFI（2026-08-27 至 2026-08-28）

- 设备：OnePlus OPD2404，Android 16 / API 36，arm64，内核 6.1.141，SELinux enforcing。
- 环境：KernelSU 3.0.0（32179），LSPosed 2.0.0（7607），Manager 1.10.1，Edge 151.0.4129.96；当前 Root/全 TLS 捕获作用域包含 Edge（UID 10311）与 Bing（UID 10312）。
- GitHub 基线验证 APK SHA-256：`bb20f391b96287f3f885c7d4ce3c5cbe9fc3ed14590e42345ddf97d76639485a`；设备安装文件哈希一致。证据目录：`device-evidence/20260827-021131-1644e18d`，manifest 复核 0 个不匹配。该哈希早于多平台/宿主全 TLS 改造，不能作为新功能验收证据。
- P0：两个 Edge 进程均记录 `DNS hooks installed=6/6` 与 `Interceptor ready`；UI 显示 Remote Preferences 已同步、API 101、同代初始化心跳。Chromium 原生 DNS 路径下 `DNS 命中 0` 属预期，不代表模块旁路。
- P1/P2：真实 GitHub 页面、API、Raw、静态资源、Release 下载和 Git smart-HTTP 端点通过；安全连接保持系统证书校验。Edge TCP/443 与 DNS 规则有实际命中，UDP/443 命中 CIDR REJECT；非作用域 shell UID 不命中 TCP 重定向。
- P3：活动下载连接跨原子规则刷新保持 ESTABLISHED；模块进程 `SIGKILL` 后约 14 秒清理规则、约 27 秒恢复完整规则；目标应用 force-stop 与用户 STOP 均未被守护器误恢复。Wi-Fi 关闭 22 秒期间服务 PID 与规则稳定，恢复后切换到新 network handle，保留候选地址但清零旧网络健康分并重新探测。
- 能力降级：设备无 `ipset`，且 ip6tables 不提供 nat 表；证据采集中的 3 条命令失败均对应这两项缺失能力。已验证受限 IPv4 inline 规则与 guardian fail-open，IPv6 透明接管未启用。
- 进程模型观察：Edge renderer 使用隔离 UID 90007，但实际外部 HTTPS socket 位于宿主主进程 PID 9215 / UID 10311；符合 Chromium renderer 只能经 network service 访问网络的模型。不得因此把所有 90000/99000 隔离 UID 粗暴加入作用域。
- 未覆盖：设备无 SIM，蜂窝切换无法执行；当前设备未安装 Google、YouTube、Discord、OpenAI 客户端；Android 12、Android 14、Magisk、GitHub App、Chrome、Brave、Firefox 和完整 IPv6 数据面仍待矩阵设备验证。
- 本次显式公网 TLS 探测通过，覆盖 14 组内置候选的系统信任链、主机名及直连/record 分片能力。
- 浏览器 TLS 终止：每设备 CA 指纹 `D7:7F:E4:E7:38:7E:96:21:70:55:E6:92:98:F8:BD:CF:BA:01:90:D9:A5:7C:E8:2D:81:BD:1F:DD:2A:0D:6E:CE` 已进入 Android 用户库；Edge 的 `CACertificates` 与 `CAPlatformIntegrationEnabled` 均显示 Platform / Device / Mandatory / OK。同一 DER 的旧 APEX 系统副本已移除。
- 上述记录早于 Edge 147+ `BuiltInDnsClientEnabled=true` / `DnsOverHttpsMode=off` 策略与 NAT64 IPv6 UID 回落实现；这两项仍是待执行真机项，不能从旧截图或旧 APK 推定通过。
- Discord Web：登录页安全连接正常；`remote-auth-gateway.discord.gg` 由 `.discord.gg` 受控后缀路由实时覆盖，WebSocket Upgrade 返回 `101` 且 TLS 验证通过；二维码首次加载、断线后自动刷新均已截图验证。Discord 原生客户端与 Voice UDP 尚未验证。
- ColorOS HANS：Root Binder 租约绑定当前应用 PID。故障注入终止助手 PID `15491` 后约 25 秒自动恢复为 PID `19321`，随后保持活动；Root/CA/TLS 数据面未失活。
- 上一次文档化的实机 Release SHA-256：`d235751124c1d5f90fb321989da9328d77ed70cdd2182d86f625e3aa4191812c`。该 APK 已覆盖安装并在 R8 单 dex 下恢复 Root helper、CA、HANS、21 条 TLS 路由及 Discord 二维码。
- 当前待实机安装候选 SHA-256：`fe261753a446f8bbd72d3064a3c02398cb1a984c1dba6d5ba3935759cf36ed5c`。主机侧 404 项测试（403 通过、1 项 opt-in 公网探测按设计跳过）、Lint、Release/Xposed/16 KiB 校验已通过；YouTube 动态后缀实机结果不得在安装前标记为通过。
- 同局域网严格 TLS 矩阵（系统信任链 + SAN 主机名，无 TrustAll）确认：`120.253.*` 多个 Google 边缘 IP 对 `ghd-probe.googlevideo.com`、`ghd-probe.ytimg.com` 可验证，而裸 `googlevideo.com`/`ytimg.com` 不可验证。该结果用于证明后缀应以代表子域探测，不替代 Android 数据面验收。

每台设备记录 ROM、内核、LSPosed/Root 管理器版本、模块 APK SHA-256、网络运营商和测试时间。至少重复一次冷启动与一次服务被杀后的恢复。

连接已授权 ADB 设备后，可先用只读脚本收集一致的基础证据；脚本会依次从 PATH、`ANDROID_SDK_ROOT`、`ANDROID_HOME` 和项目 `local.properties` 定位 `adb`。多设备环境必须显式传入序列号：

```powershell
.\scripts\collect-device-evidence.ps1 -ApkPath .\app\build\outputs\apk\release\app-release.apk
.\scripts\collect-device-evidence.ps1 -Serial <adb-serial> -ApkPath .\app\build\outputs\apk\release\app-release.apk
```

证据目录包含设备/ABI/页大小/SELinux 摘要、LSPosed/Root 与目标应用版本、设备侧模块 APK 哈希、Private DNS/HTTP 代理状态、Root 服务与进程状态、监听端口、`GHD_*` 规则及计数器、Root Relay 状态、退出原因和过滤后的模块日志。`collection-errors.txt` 汇总设备不支持或采集失败的命令；`evidence-manifest.sha256` 固化其余文件的 SHA-256，提交结果前应确认错误列表与测试设备能力一致。

隐私边界：脚本不读取 `direct_settings`，不采集 cookie、token、账号数据、页面正文、截图、SSID 或 BSSID；仅读取不含认证材料的 `root_relay_status.xml`。它不会修改设备状态，也不会替代下面的人工网络场景。

## P0：模块加载与作用域

1. 安装 APK；LSPosed 必须识别为现代模块，显示 API 101+ 元数据。
2. 打开模块应用后，UI 必须显示“远程配置：已同步”；否则服务开关、活动路由和心跳令牌尚未发布到 LSPosed Remote Preferences。目标进程中的远程偏好按设计只读。
3. 只把一个测试宿主应用加入 LSPosed 与 Root 作用域，强停后启动。应用自带网页运行时必须选择宿主包，不选择通用 WebView renderer 包。
4. UI 必须在 30 秒内显示该包/进程的 Hook 初始化心跳、框架信息和规则代次。Chromium 的 Java DNS 命中数可以为 0，但必须同时验证 Root 规则计数与实际页面流量。
5. 未加入作用域的控制应用不得出现心跳，也不得受到 DNS 或防火墙影响。
6. Root 作用域为空时启动必须失败并给出明确状态，禁止静默接管所有应用。
7. 伪造 token、包名或非 Binder 调用 UID 所属包调用 heartbeat Provider 必须被拒绝；Provider 的 query/insert/update/delete 不得暴露数据或写入能力。
8. 高频重复解析命中规则时，目标应用不得崩溃或 ANR；自动化性能测试的缓存 Hook P95 必须小于 10 ms。
9. 对 Electron-like/Cronet 宿主启用“全 TLS 捕获”后，状态必须显示其活动 UID；从普通 scope 移除该包、切换 ALL/EXCLUDED 或关闭 `real_ip_redirect` 后，对应全捕获规则必须消失。

## P1：候选系统

1. 清除应用数据并断开刷新源，首次启动仍应从内置快照得到 GitHub 路由。
2. 恢复网络并执行 REPROBE；GitHub 确认 Meta、Wire DoH、本机观测及社区种子被按信任级合并；其他平台不得读取 GitHub Meta/社区种子，只使用严格 Wire DoH、本机观测与安全历史。
3. 为探测端注入证书主机名不匹配，候选必须变为 `UNUSABLE`，不能绕过证书。
4. 注入污染样本 `199.59.148.9`；它只能出现在拦截目标中，不能出现在上游候选。
5. Wi-Fi 与蜂窝切换后，旧网络健康分不得直接复用；候选地址可以保留并在新网络重新探测。
6. 验证每域候选不超过 32、探测并发不超过 4，失败退避为 1/5/30 分钟。
7. 对 `*.googlevideo.com` 等动态子域验证：普通直连候选仍不得变成宽通配地址；同 CDN 池轮换的每个 IP 必须先用固定代表子域独立验证。跨 `endpointGroup` 的 `candidatePoolScope` 只能由带 HTTP 语义探测的锚点输出种子，且候选持久化的语义策略签名必须与当前规则精确相等；旧快照或策略变更后必须重新探测。接收域必须再做自身 TLS/语义校验。只有用户授权的 TLS 终止路径可发布显式后缀路由，且每个实际子域仍使用真实 SNI、公开证书链/主机名验证，失败即关闭。

## P2：真实 IP 与 TLS 链路

在 Chrome 分别开启和关闭 Secure DNS，执行下列检查：

| 场景 | 验收结果 |
| --- | --- |
| `https://github.com` 登录页 | TLS 证书正常，无自签 CA；页面可加载 |
| GitHub App 登录与仓库列表 | API 与静态资源均正常 |
| `https://api.github.com` | 返回正常 API 响应 |
| Raw 文件 | `raw.githubusercontent.com` 可下载 |
| Release 资源 | 跳转后的 `release-assets.githubusercontent.com` 可下载 |
| HTTPS clone/fetch | `git clone https://github.com/<owner>/<repo>.git` 成功 |
| 非 GitHub HTTPS 控制域 | 原样直连，不被错误路由 |
| `https://www.google.com` / Google 登录 | 页面与账户跳转可用，系统证书正常 |
| YouTube 首页与实际视频播放 | API、图片、`*.googlevideo.com` 分片持续加载；IPv4 TCP 回退与可达 IPv6分别记录 |
| Discord Web 与原生客户端 | API/CDN 正常，Gateway 与 `remote-auth-gateway.discord.gg` WebSocket 长连接稳定；二维码可生成/刷新；Voice UDP 单独标记不在范围 |
| ChatGPT/OpenAI Web 与原生客户端 | 登录、API、SSE/流式输出和 `ws.chatgpt.com` 可用；浏览器 TLS 终止仅允许每设备 CA + 选定 UID，证书锁定 App 必须失败关闭/回退 |

同时检查：

1. IPv4 与 IPv6 TCP/443 均命中各自模块规则；UDP/443 被 REJECT，设备不支持时才 DROP，浏览器回退 TCP。
2. 有完整 ip6tables 能力时，UI 显示 IPv6 接管已启用，`ip6tables -t nat -S GHD_6_TCP` 可见；缺任一能力时不得安装 `GHD_6_*`，UI 显示仅 IPv4。
3. JNI 正确恢复 IPv4/IPv6 原始目的地址；移除或破坏原生库后，真实 IP 重定向必须关闭。
4. 首选候选故障时第二候选在 2.5 秒内接管；服务器数据一旦回给客户端，不得重新选路。
5. ClientHello 跨多个 TLS record 时仍能在 64 KiB/1 秒上限内解析；超限、无 SNI 或未知 SNI 必须保护性透传。
6. TLS 分片不改变握手字节语义，客户端仍由系统执行正常证书验证。
7. 对显式 Electron-like 宿主，原生 DNS/Cronet 请求即使没有 Java DNS Hook 命中，也必须由 UID 全 TLS 规则进入透明监听器；启用域名按真实 SNI 分类，未知 SNI/非 TLS 按原目的地址透传。
8. 全 TLS 捕获当前只扩展 IPv4；IPv6 仍按精确候选或系统原生路径。唯一例外是已显式启用、通过出口实测、TLS 路由已发布且同代 Root IPv4/vIP 数据面 ACTIVE 的 OpenAI `NON_STRICT_NAT64`：受管 DNS 只可在已发布 exact/suffix 边界内动态把实际查询名的 AAAA 返回为 NODATA；启动/刷新事务期间必须保持原生 AAAA。无 IPv6 netfilter 时，另只允许对所选 UID 与当前快照中的精确 OpenAI `/128` 安装快速不可达兜底。分别记录 DNS 回答、IPv4/IPv6 socket、目标地址与规则计数，禁止仅凭页面“看似打开”宣称双栈通过。
9. TLS 终止启用时，用户 CA 必须由 `AndroidCAStore` 精确复验；同一 DER 不得同时存在于系统/APEX 和用户根库。选中的 Edge 147+ 必须同时具有有效 `CACertificates`、`CAPlatformIntegrationEnabled`、`BuiltInDnsClientEnabled=true` 与 `DnsOverHttpsMode=off` 策略。
10. 平台一方后缀可以动态覆盖新子域，但渲染配置不得把任意观测第三方域写成通配路由，也不得把 Google/YouTube 等平台硬转发到固定第三方 ECH CDN；NO-SNI/ECH 上游、公开证书链和真实内层主机名任一失败都必须 fail-close。

## P3：故障开放与回滚

1. **ipset 路径**：强杀 Root 服务，确认真实 IP 集合约 20 秒租约到期；独立守护器还应在心跳失效 15 秒内删除 DNS/vIP 等本模块链，以及 NAT64 固定优先级 UID rule/专属表，不形成永久黑洞。
2. **无 ipset 路径**：强杀 Root 服务，确认守护器在心跳失效 15 秒内只删除本模块明确生成的 `GHD_*` 链与有界 NAT64 策略路由。
3. 服务重启时旧代规则先清理；新代防火墙成功后 active generation 才变化。
4. 连续模拟刷新失败，服务保留最后一个安全代次或回滚，并显示失败阶段。
5. 显式开启开机启动后重启设备，服务恢复；关闭开关后重启不得自启。
6. 分别关闭 `tls_fragment_v2`、`real_ip_redirect`、`adaptive_candidates`，确认每一层都能独立回滚且不影响非作用域应用。
7. 在活动连接中执行 Wi-Fi ↔ 蜂窝切换、强停目标应用、强杀模块进程，确认无系统级 DNS/网络残留。
8. 在 Oplus 系 ROM 上终止 HANS Binder 助手，确认模块在健康检查周期内重建租约；回调错误状态必须保留并出现在诊断中，不能删除后继续伪报 ACTIVE。

## P4：OpenAI 地区与 NAT64 分层验收

1. 默认关闭 `NON_STRICT_NAT64`，先分别记录 `chatgpt.com`、`auth.openai.com`、`api.openai.com` 与 `ws.chatgpt.com` 的 TCP、TLS/ECH、HTTP/应用层结果，禁止把 `Unable to load site` 直接归因于传输失败。
2. 启用前确认 OpenAI profile、TLS 终止、每设备 CA 与 Edge 147+ CA/DNS 策略均已生效；未满足任一前置条件时开关必须拒绝激活。
3. 出口探测必须使用当前 generation 中来自 Wire DoH/安全历史等可信来源的 `auth.openai.com` IPv4 种子，不能再次依赖可能污染的系统答案；该种子必须在 NAT64 路径上重新通过公开证书与主机名验证，且 OpenAI auth trace 地区、RIPE origin ASN 与运营主体关键词必须同时匹配用户配置。
4. NAT64 路由未发布、验证失败、停止或重启期间，OpenAI AAAA 必须保持默认行为；路由发布后，受管 DNS 只可按已发布 exact/suffix 标签边界动态返回 AAAA NODATA，不得扩张到 Google、YouTube、Discord 或未知第三方域。
5. 在缺少 IPv6 netfilter 的设备上，`ip -6 rule` 只允许覆盖所选 UID，专属表只包含同一 generation 中实际发布 NAT64 TLS 路由的 exact/suffix 标签边界所覆盖的精确 `/128`；单条路由成功不得把其他未通过 ECH/证书预检的 OpenAI 域写入该表。它只作为绕过受管 DNS 的兜底，Google、YouTube、Discord 与非作用域应用不得进入该表。
6. 打开 `chatgpt.com/auth/login`，只触发一次登录按钮并确认对应账户选择页出现，不实际提交账号；随后分别检查静态资源、二维码、WebSocket 与 SSE/流式响应。
7. 地区观测匹配只记为“出口实测通过”，平台仍返回地区/账号限制时必须保留原响应并报告，不自动轮换 NAT64 供应方，也不得宣称账号策略已保证通过。
8. 关闭 NAT64、停止服务、强杀进程与切换网络后，确认受管 DNS 已恢复 AAAA，固定优先级 UID rule 和 `52xxx` 专属表均消失；原生 IPv6 恢复且其他平台无残留影响。

## 结果记录

每个失败至少保存：

- 设备矩阵编号和精确复现步骤。
- UI 中的服务状态、规则代次、候选数、最后错误和失败阶段。
- LSPosed 模块日志、`logcat` 中与 `GithubDirect` 相关的行。
- `iptables-save` / `ip6tables-save` / `ipset save` 中仅与 `GHD_` 相关的规则。
- 失败域名、解析类型、候选能力、网络类型和耗时；不得保存 cookie、token 或页面正文。

完成全部三台设备矩阵前，发布状态应表述为“代码门禁通过，真机矩阵待验收”，不能宣称 Android 12–16、Magisk/KernelSU 已全部验证。
