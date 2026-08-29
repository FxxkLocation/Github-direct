# Electron-like 客户端与多平台直连计划

## 结论

GitHub 继续作为稳定回归基线；Google、YouTube、Discord、OpenAI/ChatGPT 复用同一 Root/LSPosed 数据面，按平台独立启用。Android 不直接运行 Electron：Electron 官方目标平台是 Windows、macOS 和 Linux。Android 侧需要覆盖的是 WebView、Cronet、GeckoView、CEF/Crosswalk 等宿主客户端。

标准 Chromium/WebView renderer 运行在隔离进程，但 renderer 的网络访问经 Chromium network service；Android WebView 的 network service 默认在宿主进程内。Cronet同样是嵌入宿主应用的 Chromium 网络栈。因此主作用域是宿主包 UID，不是所有 `u0_i*` renderer UID。

参考：

- [Electron 官方平台说明](https://www.electronjs.org/docs/latest)
- [Android WebView 多进程说明](https://developer.android.com/reference/android/webkit/WebView#getWebViewRenderProcess())
- [Android WebView Network Service](https://chromium.googlesource.com/chromium/src/+/HEAD/android_webview/browser/network_service/README.md)
- [Android Cronet](https://developer.android.com/develop/connectivity/cronet)
- [Chromium 多进程与 renderer 网络边界](https://www.chromium.org/developers/design-documents/multi-process-architecture/)

## 数据路径

```text
宿主应用 UID
  ├─ Java/System DNS ───────────────→ LSPosed 缓存 Hook / Root DNS
  ├─ WebView/Cronet 原生 DNS/DoH ──→ 可能绕过 Java Hook
  ├─ IPv4 QUIC/UDP 443 ────────────→ 显式宿主 REJECT/DROP，回退 TCP
  └─ IPv4 TCP 443 ─────────────────→ 精确目标规则
                                      或显式宿主全 TLS 捕获
                                          ├─ 启用平台真实 SNI → 候选竞速/ClientHello 分片
                                          ├─ 已授权平台后缀   → 可选每设备 CA + 严格 ECH 终止
                                          └─ 其他/未知 SNI    → SO_ORIGINAL_DST 原样透传

IPv6
  ├─ 有完整 ip6tables NAT 能力 → 仅精确已知候选进入中继
  └─ 无 IPv6 NAT 能力          → 默认保持系统原生直连，供可达双栈/流媒体使用
      └─ 显式 OpenAI NON_STRICT_NAT64
         且路由已实测发布     → 受管 DNS 按已发布精确/后缀边界动态抑制 AAAA
                                + 仅所选 UID 的当前精确 /128 兜底
                                → 回落到 IPv4/vIP/NAT64
```

全 TLS 捕获只允许 `SELECTED_APPS` 中经过二次选择的包，默认空集合。它不应用于 ALL/EXCLUDED scope，不接管模块自身 UID，也不会把 renderer 隔离 UID全局加入规则。

## 平台范围

| 平台 | 核心路径 | IPv6 | 长连接/流媒体 | 当前状态 |
| --- | --- | --- | --- | --- |
| GitHub | Web/API/Raw/Assets/Release/HTTPS Git | 基线仍抑制普通 AAAA | Release/clone TCP | Android 16 + Edge IPv4 已验证 |
| Google | `google.com`、账户、API、gstatic/ggpht、reCAPTCHA、1e100、gvt | 保留 AAAA | 登录/下载 | `NEEDS_VERIFY` |
| YouTube | Web、Innertube API、ytimg、动态 googlevideo | 保留 AAAA | 视频分片；IPv6可直接使用 | `NEEDS_VERIFY` |
| Discord | API、Gateway、Remote Auth、CDN、Media | 保留 AAAA | Web/二维码 WebSocket 已验证；原生客户端与 Voice UDP/3478 待验证 | `NEEDS_VERIFY` |
| OpenAI | API、ChatGPT、Android、Auth、静态/内容域 | 保留 AAAA | SSE/流式输出、`ws.chatgpt.com` | `NEEDS_VERIFY` |

域名来源分别采用 Google 官方 Chrome/Workspace 清单、Discord Developer 文档和 OpenAI Network recommendations。Google 公布的服务 IP 段会变化，并与 Google Cloud 范围存在集合关系；当前设备没有 ipset，宽 CIDR 还会挤占 128 条 inline 上限，因此首版只加入逐主机严格验证的精确候选，不把整个 Google 地址空间导入防火墙。

## 候选与 TLS 安全边界

1. GitHub：内置版本快照、官方 Meta、固定 IP Wire DoH、本机 DNS 观测、限龄社区种子。
2. 其他平台：固定 IP Wire DoH、本机 DNS 观测、安全历史；不复用 GitHub Meta/社区种子。
3. 新地址必须通过 TCP、目标探测名的真实 SNI、系统信任链和主机名验证，才可成为上游；显式同 CDN 池只在 `candidatePoolScope` 内共享 IP 种子，不共享源域的验证结论。如果 scope 跨越多个 `endpointGroup`，只有带 HTTP 语义探测的锚点可以输出种子。
4. 污染/探测失败地址只能进入 `interceptOnly`，禁止作为上游。
5. 普通直连/分片候选按精确目标发布。对于证书只覆盖 `*.domain`、裸域不提供服务的动态 CDN，候选系统使用固定一层代表子域验证边缘能力；这不会生成任意新规则，也不会改写实际请求 SNI。
6. 可选 TLS 终止只接受已启用 profile 明确声明的一方后缀。NO-SNI 固定 IP 必须先通过代表子域验证；ECH 查询目标自身 HTTPS RR，不硬编码第三方 CDN。实际连接继续按真实内层域验证公开证书，失败即关闭；未知第三方后缀不自动进入 CA 边界。
7. 每设备 CA 的私钥仅位于应用私有目录；公开证书通过 Android 用户库和浏览器策略安装。证书锁定原生 App 不属于该路径的兼容承诺。
8. Edge 147+ 的完整浏览器策略同时包含 CA 信任、平台 CA 集成、内置明文 DNS 与关闭 DoH；模块只修复自己拥有的值，不覆盖已有外部管理策略。这样 Google/OpenAI 查询保留 Edge UID，才能进入按应用作用域的 Root DNS。
9. `NON_STRICT_NAT64` 只用于规则资产显式标记的 OpenAI 域。出口探测固定使用当前 generation 的可信来源 `auth.openai.com` IPv4 种子，并在 NAT64 路径重新验证公开证书/主机名，再交叉验证 OpenAI auth 边缘地区、RIPE ASN 与 holder；地区匹配不等于账号策略保证。
10. NAT64 的动态域名适配不维护运行时精确域名清单：只有出口和 TLS 路由均验证通过、路由已发布且同代 Root IPv4/vIP 数据面 ACTIVE 后，受管 DNS 才沿该路由原有的 exact/suffix 标签边界对真实查询名返回 AAAA NODATA。启动/刷新事务、停止或失败期间保持原生 AAAA；精确 `/128` UID 策略路由仅作为绕过受管 DNS 时的有界兜底。

## 交付阶段

1. **已完成：通用路由层**
   - 启用 profile 动态生成候选目标；禁用平台会从活动快照移除。
   - A 使用 vIP；未抑制的 AAAA 只使用验证表/严格 DoH，不回退污染 raw DNS。
   - 透明监听器按启用规则识别任意平台 SNI。

2. **已完成：Electron-like 宿主数据面**
   - 增加二次授权包集合与 UID 可观测状态。
   - SELECTED 共享目标链之后增加 IPv4 TCP/443 兜底；非目标原样透传。
   - 同一宿主 IPv4 UDP/443 回退 TCP；IPv6 不做无边界全捕获。

3. **实现已更新、待用户指令验证：Google 候选池、Edge DNS 与 OpenAI IPv6 回落**
   - Google/YouTube 候选池拆分为显式 scope；Google 核心域由语义锚点动态提供待验证 IP，并补入 `*.ggpht.com` / `*.recaptcha.net` 平台根。
   - 路由快照升级为 v2，持久化 HTTP 语义策略签名；v1 候选池历史不会被新版继承。
   - Edge 147+ 合并 `BuiltInDnsClientEnabled=true` / `DnsOverHttpsMode=off`，使浏览器 DNS 保留宿主 UID。
   - NAT64 出口只接受动态严格 OpenAI 候选，并验证地区/ASN/运营主体。
   - 已发布 NAT64 路由的 exact/suffix 边界会动态驱动受管 DNS 的 AAAA NODATA；无 IPv6 netfilter 时再使用有界 `ip -6 rule uidrange` + 当前精确 /128 不可达表兜底。停止与 guardian 均精确清理。

4. **部分完成：历史设备验证**
   - 安装新 APK，确认 LSPosed/Root scope 与设置迁移。
   - Edge/系统 WebView 验证宿主 UID、非目标透传与故障开放。
   - Discord Web 与二维码 Remote Auth 已在 Edge 151 验证；Google、YouTube、OpenAI 和各平台原生客户端仍待补齐。

5. **待完成：平台功能矩阵**
   - Google 登录/账户跳转；YouTube 实际播放和续传；Discord Gateway；ChatGPT SSE/WebSocket。
   - 分别记录 IPv4/IPv6、TCP/QUIC、候选能力、iptables 计数、崩溃/ANR。
   - 补 Android 12/14、Magisk、蜂窝网络和完整 IPv6 NAT 设备。

## 验收门槛

- 离线单测、Lint、Release/Xposed/API 101 门禁全部通过。
- Hook 缓存热路径 P95 小于 10 ms；首候选失败切换小于 2.5 秒。
- 全 TLS 捕获的非目标 HTTPS 内容和目的地址不被改写。
- 服务异常后 `GHD_*` 规则在 guardian 时限内清除，不形成黑洞。
- 证书不匹配候选永不提升；可选 CA 只允许每设备生成、精确安装/删除和选定 UID 使用，私钥不得导出。
- 未完成对应客户端、网络和协议验证的平台保持 `NEEDS_VERIFY`、默认关闭。
