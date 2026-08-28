# Patched sni-gate provenance

GitHub-direct bundles `sni-gate` under its upstream dual MIT/Apache-2.0 license.
The reproducible source is:

- Repository: <https://github.com/racpast/sni-gate>
- Tag: `v2.1.0`
- Commit: `d121894dbb94dad4706307b132b8048e29aa142f`
- Project patch: `patches/0001-opt-in-clienthello-record-fragmentation.patch`
- Android NDK: `28.2.13676358`, API 24, 16 KiB PT_LOAD alignment

Build all packaged ABIs from the pinned source and locked Cargo graph:

```powershell
.\scripts\build-patched-sni-gate.ps1 -InstallAssets
```

After replacing assets, update `SniGateRuntime.EXPECTED_SHA256`, run the Android
unit suite, and run `verifyReleaseApkContract`. The script refuses a dirty or
wrong-revision source checkout and reverses only the exact patch it applied.

## Patch boundary

`fragment_client_hello = true` is opt-in and valid only for a terminating
`type = "tls"` route. It buffers at most 64 KiB, preserves the complete TLS
handshake bytes, changes only TLS record/TCP write boundaries, paces writes,
and becomes a transparent stream after the first ClientHello. Malformed or
incomplete input fails closed. rustls still performs normal public-chain and
upstream-hostname verification.

The feature passed the upstream serial test suite and an arm64 Android control
route. On the tested network, however, it did not make the blocked Google or
YouTube candidates complete TLS: those addresses still reset or timed out.
Likewise, using `g.cn`, `www.google.com`, or `www.gstatic.com` as a fixed front
name did not route YouTube content and is intentionally absent from production
configuration. A route must pass target-specific end-to-end verification before
publication; a successful TLS handshake or a generic Google 404 is insufficient.
