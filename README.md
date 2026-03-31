# GitHub Direct

[![Xposed Repo](https://img.shields.io/badge/Xposed%20Repo-available-blue?style=flat-square)](https://github.com/Xposed-Modules-Repo/org.xiyu.githubdirect)
[![Release](https://img.shields.io/github/v/release/FxxkLocation/Github-direct?style=flat-square)](https://github.com/FxxkLocation/Github-direct/releases)
[![Stars](https://img.shields.io/github/stars/FxxkLocation/Github-direct?style=flat-square)](https://github.com/FxxkLocation/Github-direct/stargazers)
[![Forks](https://img.shields.io/github/forks/FxxkLocation/Github-direct?style=flat-square)](https://github.com/FxxkLocation/Github-direct/network/members)
[![Issues](https://img.shields.io/github/issues/FxxkLocation/Github-direct?style=flat-square)](https://github.com/FxxkLocation/Github-direct/issues)
[![Size](https://img.shields.io/badge/Size-~40KB-brightgreen?style=flat-square)](#)
[![Telegram](https://img.shields.io/badge/Telegram-加入群组-blue?style=flat-square&logo=telegram)](https://t.me/+BUfEUGzViTg2YWU1)

**GitHub Direct** 是一款专为 Android 平台设计的轻量级应用/Xposed（LibXposed）模块，旨在解决大陆地区访问 GitHub（包括代码仓库、API、Raw文件、静态资源等）时的 DNS 污染和 SNI 阻断问题。

整个项目采用极致精简的架构开发，Release 版 APK 仅约 **40 KB**。

---

## 技术细节

本应用结合了多种底层安卓系统与网络技术，在不依赖臃肿第三方库的情况下实现极速的直连方案：

1. **DNS over HTTPS (DoH) 与内置防断网回退（Fallback）**
   - 传统 UDP 53 端口的 DNS 查询极易被劫持和污染。本项目使用了基于 HTTPS 的 DNS 解析（DoH），结合可信的 DNS 节点获取 GitHub 真正的未屏蔽 IP。
   - 当 DoH 接口本身遭到过滤时，系统会触发 Fallback 机制，自动调用应用内硬编码（动态更新）的一批干净的 GitHub 服务器真实 IP，确保在极端恶劣网络环境下依然能够寻址。

2. **双轨网络分流 (VPN Service & Xposed Hook)**
   - **VPN 模式流量代理**：无需 Root 权限，通过 Android 原生 `VpnService` 构建本地虚拟网卡。应用在本地接管终端发出的 DNS 解析请求与特定端口（如 443）的握手包，并进行透明重定向，实现全机/特定应用的 GitHub 访问修复。
   - **Xposed (LibXposed) 模式**：通过模块注入到被代理 App 进程中（如 GitHub 官方安卓客户端）。应用会在底层 Hook 诸如 `UrlConnection` 或 `OkHttp` 的网络建立流程，在发起 TLS 握手前**动态修改 SNI (Server Name Indication) 和 Host Header**，由于流量表现为合法的特征，从而有效穿透深度包检测 (DPI)。

3. **原生极简 UI 与极限 R8 缩包**
   - **0 依赖**：完全摒弃了 Jetpack Compose 或 Material Components 等动辄几十上百兆的臃肿 UI 框架。界面基于原生 XML 布局与手写的 SVG Vector Drawables 构建，遵循 GitHub Primer 设计规范，带来了流畅且原生的视觉体验。
   - **R8 深度优化**：开启了高强度的代码混淆、资源压缩以及无效代码剔除（Dead Code Elimination）。在 Release 编译阶段，R8 将未用到的 Kotlin 标准库完全剥离，最终将应用体积压缩至极致的 **40多 KB**。

---

## 使用方法

应用提供了两种运行模式，可以根据你的设备环境自由选择：

### 模式一：免 Root VPN 代理模式
适用于**未 Root** 的普通设备，通过建立本地虚拟专用网络来接管流量。

1. 下载并安装本应用。
2. 打开 **GitHub Direct**。
3. 点击主页上的 **“开启代理”** 按钮。
4. 在系统弹出的 “网络连接请求” (VPN 授权) 提示框中，选择 **允许/确定**。
5. 当界面状态变为 “已开启” 且显示绿色指示灯后，即可打开浏览器或其他工具顺畅访问 GitHub。
6. 使用完毕后，可返回 App 点击 “关闭代理”。

### 模式二：Xposed 框架模块模式
适用于**已 Root**，并且安装了 LSPosed (或支持 LibXposed 的框架) 的高级用户。代理更为底层且无感。

1. 下载并安装本应用。
2. 打开 LSPosed 管理器，在模块列表中找到 **GitHub Direct** 并启用它。
3. 在模块的作用域（Scope）中，勾选你需要修复 GitHub 访问的应用（例如 GitHub 官方客户端、各种第三方下载器等）。
4. 强行停止目标应用或重启系统。
5. 打开本应用可以查看 “模块状态” 是否显示 “已激活”；打开目标应用即可体验直连。

---

## 内置诊断工具

App 主界面提供了两个排障按钮，方便随时测试当前设备连接 Github 的状态：
- **测试 DNS**：将分别通过 DoH 和本地防污染 IP 强行解析各大 GitHub 域名，并在输出日志面板打印解析所得的详细 IP 结果。
- **测试连通性**：通过建立真实的 Socket/ICMP 连接探测 GitHub 服务器连通状况与延迟（单位：毫秒）。

---

## 作者与交流

- **Created by**: Mai_xiyu
- **GitHub Repository**: [FxxkLocation/Github-direct](https://github.com/FxxkLocation/Github-direct)

如果您遇到任何使用上的问题、或者有提供干净 IP 的建议，欢迎给此项目提交 Issue，或者加入我们的 Telegram 讨论群交流：

[加入 Telegram 群组](https://t.me/+BUfEUGzViTg2YWU1)

喜欢这个项目的话，别忘了点击上方的 **Star** 支持一下！
