# Github-direct

[English](README.md) | 简体中文

[![Latest release](https://img.shields.io/github/v/release/FxxkLocation/Github-direct?style=flat-square)](https://github.com/FxxkLocation/Github-direct/releases/latest)
[![Android](https://img.shields.io/badge/Android-8.0%2B-3DDC84?style=flat-square&logo=android)](https://developer.android.com/)
[![LSPosed API](https://img.shields.io/badge/LSPosed_API-101%2B-6f42c1?style=flat-square)](https://github.com/LSPosed/LSPosed)
[![License](https://img.shields.io/github/license/FxxkLocation/Github-direct?style=flat-square)](LICENSE)

Github-direct 是面向 Android Root / LSPosed 环境的选择性网络连通性模块。它将防污染 DNS、经过验证的候选地址、透明 TCP/TLS 中继和故障开放保护组合为一个按应用授权的数据面。

GitHub 是目前完成端到端真机验证的稳定基线。Google、YouTube、Discord 和 OpenAI / ChatGPT 已接入同一套 profile 与路由系统，但仍属于实验能力，默认关闭，必须在具体设备和网络上单独验证。

## 主要能力

- **现代 LSPosed 模块**：使用 LibXposed API 102，最低兼容 API 101。
- **明确的应用作用域**：LSPosed Hook 与 Root 数据面分别授权；空 Root 作用域不会退化为全局接管。
- **动态候选系统**：合并可信 DNS、内置安全快照和受限历史结果，并通过 TCP、系统信任链、主机名及端点语义验证候选。
- **Root 透明模式**：仅接管所选 UID 的目标 DNS、TCP/443 和必要的 QUIC 回退；IPv4 与 IPv6 规则独立探测、事务安装并统一回滚。
- **真实目的地址恢复**：通过 JNI 读取 `SO_ORIGINAL_DST`；原生能力不可用时关闭相关重定向，不盲目接管连接。
- **TLS 中继**：解析多 record ClientHello，按虚拟 IP、允许的 SNI 或原目的地址选择路由；无法可靠归类时原样透传。
- **可选浏览器 TLS 终止**：仅限用户二次授权的浏览器/宿主 UID，并要求每设备 CA、严格上游证书/主机名验证以及受控后缀边界。
- **故障开放**：能力探测、监听器、规则安装或校验失败时撤销本模块的 `GHD_*` 规则；独立 guardian 清理异常退出后的残留。
- **可观测性**：界面显示活动代次、Root UID、候选数量、Hook 心跳、DNS 命中以及稳定的失败阶段。

## 工作原理

1. 受管 DNS 只为已启用 profile 的域名返回虚拟地址或经过验证的真实地址。
2. Root 规则只将所选应用的对应连接导向本地监听器，并排除模块自身 UID。
3. 中继读取 ClientHello 和原始目的地址，从当前不可变规则快照中选择候选。
4. 候选连接保持真实目标主机名、公开证书链与主机名校验；普通路径不解密或改写 HTTPS 内容。
5. 新一代规则只有在监听器、iptables 和快照均验证成功后才发布；失败则回滚到原生网络路径。

## 兼容范围

| 项目 | 当前范围 |
| --- | --- |
| Android | Android 8.0+；首期真机验收范围 Android 12–16；`minSdk=26`、`targetSdk=36` |
| LSPosed | 现代 API 101+；编译 API 102 |
| Root | Magisk / KernelSU；需要可用的 `su`、iptables、owner 与 REDIRECT |
| IPv6 | 只有 ip6tables nat/OUTPUT、owner、REDIRECT、save/restore 与 IPv6 监听全部可用时才接管 |
| ABI | arm64-v8a、armeabi-v7a、x86_64 |
| 原生页大小 | ELF LOAD 对齐 16 KiB |
| 网络范围 | HTTPS/TCP 443；UDP/443 仅用于促使目标应用从 QUIC 回退 TCP |

## 安装与使用

1. 从 [Releases](https://github.com/FxxkLocation/Github-direct/releases) 下载并安装 APK。
2. 在 LSPosed 中启用模块，只选择需要处理的应用，然后强行停止并重新启动目标应用。
3. 打开 Github-direct 并授予 Root。在 Root 作用域中选择相同的应用。
4. 优先使用“自动选择（Root 优先）”；无 Root 环境可以选择 VPN 模式。
5. 仅在 WebView、Cronet 或内置 Chromium 宿主的普通路径无法覆盖时，才对该宿主二次启用“内置运行时全 TLS 捕获”。
6. 按需启用平台 profile，并在状态页确认 Root 服务、活动代次、候选数量和失败阶段。

### 后端模式

- **自动选择**：设备具备完整 Root 能力时优先使用透明后端，否则回退到可用模式。
- **Root 透明模式**：不占用 Android VPN 槽位，按 UID 安装有界 iptables 规则。
- **VPN 模式**：使用 Android `VpnService`，适用于没有 Root 或 Root netfilter 能力不完整的设备。
- **Xposed（DNS + Root 中继）**：Hook 提供进程内 DNS 覆盖，Root 后端负责透明连接中继。

## 平台状态

| Profile | 状态 | 说明 |
| --- | --- | --- |
| GitHub | 已验证基线 | 浏览器、HTTPS Git、API、Raw、静态资源和 Release 下载已完成真机验证 |
| Google | 实验性 | 默认关闭；登录和不同客户端需要分别验证 |
| YouTube | 实验性 | 默认关闭；页面资源与视频媒体链路需要分别验证 |
| Discord | 实验性 | Discord Web 与二维码登录 WebSocket 已有真机结果；原生客户端未完成全链路验收 |
| OpenAI / ChatGPT | 实验性 | 默认关闭；网络可达不代表账号或地区策略必然允许 |

## 可选 CA 与 TLS 终止

普通候选与 ClientHello 分片路径不需要安装 CA。只有浏览器路径在可见 SNI/普通中继均不足时，才考虑 TLS 终止：

- CA 按设备生成，私钥仅保存在应用私有目录，Root 所有且权限为 `0600`。
- 公开 CA 必须在 Android 信任库中重新读取并校验后才能使用。
- 终止范围同时受所选 UID、已启用 profile 和明确后缀约束。
- 上游仍必须通过公开证书链、真实主机名以及 profile 要求的 ECH/语义验证。
- 证书锁定的原生应用不保证兼容，应继续使用非解密路径。

## 安全边界

- 不扫描公网地址；候选只来自已配置的可信来源和有界历史快照。
- 污染 DNS 地址只能进入待拦截目标集，不能直接成为上游候选。
- 不使用 TrustAll，不关闭主机名验证，不接受无效证书。
- 不安装默认路由，不静默切换第三方出口，也不声称绕过平台账号或地区策略。
- Hook 热路径只读取不可变快照；配置不可用或异常时保护性放行。
- 模块只删除自己生成的链、集合、策略规则和精确 CA，不清理其他应用的网络配置。

## 构建

需要 JDK 21、Android SDK Platform / Build Tools 37.0、NDK 28.2.13676358 和 CMake 3.22.1。

```bash
./gradlew testDebugUnitTest lintDebug verifyXposedReleaseApk --no-daemon
```

最低框架 API 兼容检查：

```bash
./gradlew compileDebugJavaWithJavac \
  --init-script gradle/verify-libxposed-101.init.gradle \
  --no-daemon
```

`verifyXposedReleaseApk` 会构建 Release APK，并校验现代 Xposed 元数据、三个 JNI ABI、每个 ELF 的 16 KiB LOAD 对齐以及 `zipalign -c -P 16`。

真机验收步骤和证据模板见 [docs/VALIDATION.md](docs/VALIDATION.md)。

> 当前 Release 构建沿用项目现有的 debug signing。正式分发前应迁移到受控的 release keystore，并公开证书指纹和迁移策略。

## 项目链接

- 源码与 Issue：[FxxkLocation/Github-direct](https://github.com/FxxkLocation/Github-direct)
- LSPosed 模块仓库：[Xposed-Modules-Repo/org.xiyu.githubdirect](https://github.com/Xposed-Modules-Repo/org.xiyu.githubdirect)
- 许可证：[LICENSE](LICENSE)
