[CmdletBinding()]
param(
    [string]$SourceDirectory = "",
    [string]$AndroidSdkDirectory = "",
    [switch]$InstallAssets
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$upstreamUrl = "https://github.com/racpast/sni-gate.git"
$upstreamCommit = "d121894dbb94dad4706307b132b8048e29aa142f"
$ndkVersion = "28.2.13676358"
$androidApi = 24
$patchPath = Join-Path $repoRoot "third_party\sni-gate\patches\0001-opt-in-clienthello-record-fragmentation.patch"

if ([string]::IsNullOrWhiteSpace($SourceDirectory)) {
    $SourceDirectory = Join-Path $repoRoot ".codex-tmp\sni-gate-patched-source"
}
$sourcePath = [System.IO.Path]::GetFullPath($SourceDirectory)

if ([string]::IsNullOrWhiteSpace($AndroidSdkDirectory)) {
    $sdkCandidates = @(
        $env:ANDROID_SDK_ROOT,
        $env:ANDROID_HOME,
        $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA "Android\Sdk" })
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $AndroidSdkDirectory = $sdkCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if ([string]::IsNullOrWhiteSpace($AndroidSdkDirectory)) {
    throw "Android SDK not found; pass -AndroidSdkDirectory"
}
$sdkPath = (Resolve-Path -LiteralPath $AndroidSdkDirectory).Path
$ndkPath = Join-Path $sdkPath "ndk\$ndkVersion"
$toolBin = Join-Path $ndkPath "toolchains\llvm\prebuilt\windows-x86_64\bin"
$llvmAr = Join-Path $toolBin "llvm-ar.exe"
$llvmReadElf = Join-Path $toolBin "llvm-readelf.exe"

foreach ($required in @($patchPath, $ndkPath, $llvmAr, $llvmReadElf)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "required path is missing: $required"
    }
}
foreach ($command in @("git", "cargo", "rustup")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "required command is missing: $command"
    }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)] [string]$Command,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$WorkingDirectory
    )
    Push-Location $WorkingDirectory
    try {
        & $Command @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Command exited with code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path -LiteralPath $sourcePath)) {
    $sourceParent = Split-Path -Parent $sourcePath
    New-Item -ItemType Directory -Path $sourceParent -Force | Out-Null
    Invoke-Checked -Command "git" -Arguments @(
        "clone", "--filter=blob:none", "--no-checkout", $upstreamUrl, $sourcePath
    ) -WorkingDirectory $repoRoot
    Invoke-Checked -Command "git" -Arguments @(
        "-C", $sourcePath, "fetch", "--depth=1", "origin", $upstreamCommit
    ) -WorkingDirectory $repoRoot
    Invoke-Checked -Command "git" -Arguments @(
        "-C", $sourcePath, "checkout", "--detach", $upstreamCommit
    ) -WorkingDirectory $repoRoot
}

if (-not (Test-Path -LiteralPath (Join-Path $sourcePath ".git"))) {
    throw "source directory is not a Git checkout: $sourcePath"
}
$head = (& git -C $sourcePath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -ne $upstreamCommit) {
    throw "source must be the pinned sni-gate commit $upstreamCommit; found $head"
}
$dirty = (& git -C $sourcePath status --porcelain)
if ($LASTEXITCODE -ne 0 -or $dirty) {
    throw "source checkout must be clean before applying the project patch"
}

$targets = @(
    [pscustomobject]@{
        Rust = "aarch64-linux-android"; Abi = "arm64-v8a"
        Clang = "aarch64-linux-android${androidApi}-clang.cmd"
        CargoSuffix = "AARCH64_LINUX_ANDROID"; CcSuffix = "aarch64_linux_android"
    },
    [pscustomobject]@{
        Rust = "armv7-linux-androideabi"; Abi = "armeabi-v7a"
        Clang = "armv7a-linux-androideabi${androidApi}-clang.cmd"
        CargoSuffix = "ARMV7_LINUX_ANDROIDEABI"; CcSuffix = "armv7_linux_androideabi"
    },
    [pscustomobject]@{
        Rust = "x86_64-linux-android"; Abi = "x86_64"
        Clang = "x86_64-linux-android${androidApi}-clang.cmd"
        CargoSuffix = "X86_64_LINUX_ANDROID"; CcSuffix = "x86_64_linux_android"
    }
)

foreach ($target in $targets) {
    $clang = Join-Path $toolBin $target.Clang
    if (-not (Test-Path -LiteralPath $clang)) {
        throw "NDK compiler is missing: $clang"
    }
    Invoke-Checked -Command "rustup" -Arguments @("target", "add", $target.Rust) -WorkingDirectory $repoRoot
}

$savedEnvironment = @{}
$environmentNames = @("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "RUSTFLAGS")
foreach ($target in $targets) {
    $environmentNames += "CARGO_TARGET_$($target.CargoSuffix)_LINKER"
    $environmentNames += "CC_$($target.CcSuffix)"
    $environmentNames += "AR_$($target.CcSuffix)"
}
foreach ($name in $environmentNames) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

$patchApplied = $false
try {
    Invoke-Checked -Command "git" -Arguments @(
        "-C", $sourcePath, "apply", "--check", $patchPath
    ) -WorkingDirectory $repoRoot
    Invoke-Checked -Command "git" -Arguments @(
        "-C", $sourcePath, "apply", $patchPath
    ) -WorkingDirectory $repoRoot
    $patchApplied = $true

    $env:ANDROID_NDK_HOME = $ndkPath
    $env:ANDROID_NDK_ROOT = $ndkPath
    $env:RUSTFLAGS = "-C link-arg=-Wl,-z,max-page-size=16384"
    $results = @()

    foreach ($target in $targets) {
        $clang = Join-Path $toolBin $target.Clang
        Set-Item -Path "Env:CARGO_TARGET_$($target.CargoSuffix)_LINKER" -Value $clang
        Set-Item -Path "Env:CC_$($target.CcSuffix)" -Value $clang
        Set-Item -Path "Env:AR_$($target.CcSuffix)" -Value $llvmAr

        Invoke-Checked -Command "cargo" -Arguments @(
            "build", "--locked", "--release", "--target", $target.Rust
        ) -WorkingDirectory $sourcePath

        $binary = Join-Path $sourcePath "target\$($target.Rust)\release\sni-gate"
        if (-not (Test-Path -LiteralPath $binary)) {
            throw "cargo did not produce $binary"
        }
        $programHeaders = & $llvmReadElf -lW $binary
        if ($LASTEXITCODE -ne 0) {
            throw "llvm-readelf failed for $($target.Abi)"
        }
        $loadHeaders = @($programHeaders | Where-Object { $_ -match '^\s*LOAD\s' })
        if ($loadHeaders.Count -eq 0 -or $loadHeaders.Where({ $_ -notmatch '\s0x4000\s*$' }).Count -gt 0) {
            throw "$($target.Abi) does not use 16 KiB PT_LOAD alignment"
        }
        $hash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        $results += [pscustomobject]@{
            Abi = $target.Abi
            Bytes = (Get-Item -LiteralPath $binary).Length
            Sha256 = $hash
            Binary = $binary
        }
    }
    if ($InstallAssets) {
        foreach ($result in $results) {
            $asset = Join-Path $repoRoot "app\src\main\assets\sni-gate\$($result.Abi)\sni-gate"
            Copy-Item -LiteralPath $result.Binary -Destination $asset -Force
        }
    }
    $results |
        Select-Object Abi, Bytes, Sha256, @{ Name = "Installed"; Expression = { [bool]$InstallAssets } } |
        Format-Table -AutoSize
    Write-Host "Patch SHA256: $((Get-FileHash -LiteralPath $patchPath -Algorithm SHA256).Hash.ToLowerInvariant())"
} finally {
    if ($patchApplied) {
        Invoke-Checked -Command "git" -Arguments @(
            "-C", $sourcePath, "apply", "--reverse", $patchPath
        ) -WorkingDirectory $repoRoot
    }
    foreach ($name in $environmentNames) {
        $oldValue = $savedEnvironment[$name]
        if ($null -eq $oldValue) {
            Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
        } else {
            Set-Item -Path "Env:$name" -Value $oldValue
        }
    }
}
