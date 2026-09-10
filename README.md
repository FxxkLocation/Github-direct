# Github-direct

English | [简体中文](README-CN.md)

[![Latest release](https://img.shields.io/github/v/release/FxxkLocation/Github-direct?style=flat-square)](https://github.com/FxxkLocation/Github-direct/releases/latest)
[![Android](https://img.shields.io/badge/Android-8.0%2B-3DDC84?style=flat-square&logo=android)](https://developer.android.com/)
[![LSPosed API](https://img.shields.io/badge/LSPosed_API-101%2B-6f42c1?style=flat-square)](https://github.com/LSPosed/LSPosed)
[![License](https://img.shields.io/github/license/FxxkLocation/Github-direct?style=flat-square)](LICENSE)

Github-direct is a selective network-connectivity module for Android Root and LSPosed environments. It combines pollution-resistant DNS, verified endpoint candidates, transparent TCP/TLS relaying, and fail-open protection in a data plane that is authorized per application.

GitHub is the stable baseline with completed end-to-end device validation. Google, YouTube, Discord, and OpenAI / ChatGPT are integrated into the same profile and routing system, but remain experimental, disabled by default, and require separate validation on each device and network.

## Highlights

- **Modern LSPosed module**: built with LibXposed API 102 and compatible with API 101 or later.
- **Explicit application scope**: LSPosed hooks and the Root data plane are authorized separately; an empty Root scope never expands into global interception.
- **Dynamic candidate system**: combines trusted DNS, bundled safety snapshots, and bounded historical results, then verifies candidates with TCP, the system trust store, hostname checks, and endpoint semantics.
- **Root transparent mode**: intercepts only target DNS, TCP/443, and required QUIC fallback traffic for selected UIDs; IPv4 and IPv6 rules are probed and installed independently but roll back as one transaction.
- **Original-destination recovery**: reads `SO_ORIGINAL_DST` through JNI. Related redirection is disabled when the native capability is unavailable.
- **TLS relay**: parses multi-record ClientHello messages and routes by virtual IP, allowed SNI, or original destination; traffic is passed through unchanged when it cannot be classified safely.
- **Optional browser TLS termination**: restricted to browser/host UIDs explicitly authorized a second time, with a per-device CA, strict upstream certificate and hostname validation, and controlled suffix boundaries.
- **Fail-open lifecycle**: removes this module's `GHD_*` rules when capability probing, listeners, installation, or verification fails; an independent guardian cleans stale state after abnormal termination.
- **Observability**: displays the active generation, Root UID, candidate counts, hook heartbeat, DNS hits, and stable failure stages.

## How it works

1. Managed DNS returns virtual or verified real addresses only for domains in enabled profiles.
2. Root rules redirect only matching connections from selected applications to local listeners and always exclude the module's own UID.
3. The relay reads the ClientHello and original destination, then selects candidates from the current immutable route snapshot.
4. Candidate connections preserve the real target hostname and enforce the public certificate chain and hostname checks. The normal path neither decrypts nor rewrites HTTPS content.
5. A new rule generation is published only after the listeners, iptables rules, and snapshot pass verification; failures roll back to the native network path.

## Compatibility

| Component | Current scope |
| --- | --- |
| Android | Android 8.0+; initial device-validation range is Android 12–16; `minSdk=26`, `targetSdk=36` |
| LSPosed | Modern API 101+; compiled against API 102 |
| Root | Magisk / KernelSU with working `su`, iptables, owner matching, and REDIRECT |
| IPv6 | Intercepted only when ip6tables nat/OUTPUT, owner, REDIRECT, save/restore, and the IPv6 listener all pass capability checks |
| ABI | arm64-v8a, armeabi-v7a, x86_64 |
| Native page size | 16 KiB ELF LOAD alignment |
| Network scope | HTTPS/TCP 443; UDP/443 is handled only to make selected targets fall back from QUIC to TCP |

## Installation and use

1. Download and install the APK from [Releases](https://github.com/FxxkLocation/Github-direct/releases).
2. Enable the module in LSPosed, select only the applications that need it, then force-stop and restart those applications.
3. Open Github-direct and grant Root access. Select the same applications in the Root scope.
4. Prefer **Auto (Root first)**. Devices without Root can use VPN mode.
5. Enable **embedded-runtime full TLS capture** for a host only when its WebView, Cronet, or embedded Chromium traffic is not covered by the normal path.
6. Enable platform profiles as needed and confirm that the status page shows a running Root service, an active generation, usable candidates, and no failure stage.

### Backend modes

- **Auto**: prefers the transparent Root backend when all required capabilities pass, otherwise falls back to an available mode.
- **Root transparent**: installs bounded per-UID iptables rules without occupying Android's VPN slot.
- **VPN**: uses Android `VpnService` for devices without Root or with incomplete Root netfilter support.
- **Xposed (DNS + Root relay)**: the hook provides in-process DNS handling while the Root backend handles transparent connection relaying.

## Platform status

| Profile | Status | Notes |
| --- | --- | --- |
| GitHub | Validated baseline | Browser, HTTPS Git, API, Raw, static assets, and Release downloads have completed device validation |
| Google | Experimental | Disabled by default; sign-in and individual clients require separate validation |
| YouTube | Experimental | Disabled by default; page assets and video-media paths must be validated separately |
| Discord | Experimental | Discord Web and QR-login WebSocket have device results; the native client has not completed end-to-end acceptance |
| OpenAI / ChatGPT | Experimental | Disabled by default; network reachability does not guarantee account or regional-policy acceptance |

## Optional CA and TLS termination

The normal candidate and ClientHello-fragmentation paths do not require a CA. Consider TLS termination only for browser traffic when visible-SNI and pass-through relaying are insufficient:

- The CA is generated per device; its private key remains in app-private storage, is Root-owned, and uses mode `0600`.
- The public CA must be read back and verified from the Android trust store before use.
- Termination is bounded simultaneously by selected UIDs, enabled profiles, and explicit domain suffixes.
- Upstream connections must still pass public-chain, real-hostname, and profile-required ECH or semantic validation.
- Certificate-pinned native applications are not guaranteed to work and should remain on non-decrypting paths.

## Security boundaries

- The module does not scan public address space; candidates come only from configured trusted sources and bounded historical snapshots.
- Polluted DNS addresses may enter the interception target set but cannot become upstream candidates without verification.
- No TrustAll, disabled hostname verification, or invalid certificate acceptance is used.
- The module does not install a default route, silently switch to a third-party egress, or claim to bypass account or regional policies.
- Hook hot paths read immutable snapshots only and fail open when configuration is unavailable or invalid.
- Cleanup is limited to chains, sets, policy rules, and exact CA material created by this module.

## Building

The project requires JDK 21, Android SDK Platform / Build Tools 37.0, NDK 28.2.13676358, and CMake 3.22.1.

```bash
./gradlew testDebugUnitTest lintDebug verifyXposedReleaseApk --no-daemon
```

Minimum framework API compatibility check:

```bash
./gradlew compileDebugJavaWithJavac \
  --init-script gradle/verify-libxposed-101.init.gradle \
  --no-daemon
```

`verifyXposedReleaseApk` builds the release APK and verifies modern Xposed metadata, all three JNI ABIs, 16 KiB LOAD alignment for every ELF, and `zipalign -c -P 16`.

See [docs/VALIDATION.md](docs/VALIDATION.md) for device acceptance steps and evidence templates.

> The current release build retains the project's existing debug signing configuration. Before production distribution, migrate to a controlled release keystore and publish its certificate fingerprint and migration policy.

## Project links

- Source and issues: [FxxkLocation/Github-direct](https://github.com/FxxkLocation/Github-direct)
- LSPosed module repository: [Xposed-Modules-Repo/org.xiyu.githubdirect](https://github.com/Xposed-Modules-Repo/org.xiyu.githubdirect)
- License: [LICENSE](LICENSE)
