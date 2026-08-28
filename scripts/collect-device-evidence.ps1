[CmdletBinding()]
param(
    [string]$Serial = "",
    [string]$ApkPath = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$collectionErrors = [System.Collections.Generic.List[string]]::new()

function Resolve-AdbPath {
    $command = Get-Command adb -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($command) {
        return $command.Source
    }

    $sdkRoots = [System.Collections.Generic.List[object]]::new()
    if ($env:ANDROID_SDK_ROOT) {
        $sdkRoots.Add([pscustomobject]@{
            Source = "ANDROID_SDK_ROOT"
            Path = $env:ANDROID_SDK_ROOT
        })
    }
    if ($env:ANDROID_HOME) {
        $sdkRoots.Add([pscustomobject]@{
            Source = "ANDROID_HOME"
            Path = $env:ANDROID_HOME
        })
    }

    $localProperties = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\local.properties"))
    if (Test-Path -LiteralPath $localProperties -PathType Leaf) {
        foreach ($line in Get-Content -LiteralPath $localProperties) {
            if ($line -match '^\s*sdk\.dir\s*=\s*(.*?)\s*$') {
                $decoded = $Matches[1].Trim().Trim('"')
                $decoded = $decoded.Replace('\:', ':').Replace('\\', '\')
                if ($decoded) {
                    $sdkRoots.Add([pscustomobject]@{
                        Source = "local.properties sdk.dir"
                        Path = $decoded
                    })
                }
                break
            }
        }
    }

    $checked = [System.Collections.Generic.List[string]]::new()
    foreach ($sdkRoot in $sdkRoots) {
        foreach ($executable in @("adb.exe", "adb")) {
            $candidate = Join-Path ([string]$sdkRoot.Path) "platform-tools\$executable"
            $checked.Add("$($sdkRoot.Source) -> $candidate")
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return (Resolve-Path -LiteralPath $candidate).Path
            }
        }
    }

    $checkedText = if ($checked.Count -gt 0) {
        "PATH; " + ($checked -join "; ")
    } else {
        "PATH; ANDROID_SDK_ROOT; ANDROID_HOME; $localProperties"
    }
    throw "Unable to locate adb. Install Android SDK Platform-Tools or configure the SDK path. Checked: $checkedText"
}

$script:AdbPath = Resolve-AdbPath

function Invoke-Adb {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $prefix = @()
    if ($Serial) { $prefix = @("-s", $Serial) }
    $output = @(& $script:AdbPath @prefix @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "adb $($Arguments -join ' ') failed: $($output -join [Environment]::NewLine)"
    }
    return $output
}

function Invoke-Root {
    param([Parameter(Mandatory = $true)][string]$Command)
    return Invoke-Adb -Arguments @("shell", "su", "-c", $Command)
}

function Get-CapturedSection {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [switch]$Optional
    )

    $result = [System.Collections.Generic.List[string]]::new()
    $result.Add("[$Label]")
    try {
        $lines = @(& $Action)
        if ($lines.Count -eq 0) {
            $result.Add("<no output>")
        } else {
            foreach ($line in $lines) {
                $result.Add([string]$line)
            }
        }
    } catch {
        $message = $_.Exception.Message
        $result.Add("ERROR: $message")
        if (-not $Optional) {
            $script:collectionErrors.Add("${Label}: $message")
        }
    }
    $result.Add("")
    return $result.ToArray()
}

function Save-Lines {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [scriptblock]$Filter = { param($lines) $lines }
    )

    $target = Join-Path $OutputDirectory $Name
    try {
        $lines = @(& $Action)
        $selected = @(& $Filter $lines)
        if ($selected.Count -eq 0) {
            $selected = @("<no output>")
        }
        $selected | Set-Content -LiteralPath $target -Encoding utf8
    } catch {
        $message = $_.Exception.Message
        "ERROR: $message" | Set-Content -LiteralPath $target -Encoding utf8
        $script:collectionErrors.Add("${Name}: $message")
    }
}

if (-not $Serial) {
    $deviceOutput = @(& $script:AdbPath devices -l 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "adb devices -l failed: $($deviceOutput -join [Environment]::NewLine)"
    }
    $devices = @($deviceOutput |
        Where-Object { $_ -match '^([^\s]+)\s+device(?:\s|$)' } |
        ForEach-Object { ($_ -split '\s+')[0] })
    if ($devices.Count -eq 0) { throw "No authorized adb device is connected." }
    if ($devices.Count -gt 1) { throw "Multiple devices are connected; pass -Serial explicitly." }
    $Serial = $devices[0]
}

Invoke-Adb -Arguments @("get-state") | Out-Null

if (-not $OutputDirectory) {
    $safeSerial = $Serial -replace '[^A-Za-z0-9_.-]', '_'
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputDirectory = Join-Path $PSScriptRoot "..\device-evidence\$stamp-$safeSerial"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$properties = @(
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.fingerprint",
    "ro.product.cpu.abilist",
    "ro.product.cpu.abi",
    "ro.boot.slot_suffix",
    "ro.boot.verifiedbootstate"
)
$summary = [System.Collections.Generic.List[string]]::new()
$summary.Add("serial=$Serial")
$summary.Add("collected_at=$([DateTimeOffset]::Now.ToString('o'))")
$summary.Add("adb=$script:AdbPath")
$summary.Add("collector_sha256=$((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant())")
foreach ($property in $properties) {
    $value = ([string](Invoke-Adb -Arguments @("shell", "getprop", $property) |
        Select-Object -First 1)).Trim()
    $summary.Add("$property=$value")
}
$kernel = ([string](Invoke-Adb -Arguments @("shell", "uname", "-a") |
    Select-Object -First 1)).Trim()
$summary.Add("kernel=$kernel")

try {
    $pageSize = ([string](Invoke-Adb -Arguments @("shell", "getconf", "PAGESIZE") |
        Select-Object -Last 1)).Trim()
    $summary.Add("page_size=$pageSize")
} catch {
    $summary.Add("page_size=ERROR: $($_.Exception.Message)")
    $collectionErrors.Add("getconf PAGESIZE: $($_.Exception.Message)")
}

try {
    $selinux = ([string](Invoke-Adb -Arguments @("shell", "getenforce") |
        Select-Object -Last 1)).Trim()
    $summary.Add("selinux=$selinux")
} catch {
    $summary.Add("selinux=ERROR: $($_.Exception.Message)")
    $collectionErrors.Add("getenforce: $($_.Exception.Message)")
}

try {
    $rootUid = ([string](Invoke-Root -Command "id -u" |
        Select-Object -Last 1)).Trim()
    $summary.Add("root_uid=$rootUid")
} catch {
    $summary.Add("root_uid=ERROR: $($_.Exception.Message)")
    $collectionErrors.Add("root id -u: $($_.Exception.Message)")
}

if ($ApkPath) {
    $resolvedApk = (Resolve-Path -LiteralPath $ApkPath).Path
    $apk = Get-Item -LiteralPath $resolvedApk
    if ($apk.PSIsContainer) { throw "ApkPath must point to an APK file: $resolvedApk" }
    $hash = Get-FileHash -LiteralPath $resolvedApk -Algorithm SHA256
    $summary.Add("apk=$resolvedApk")
    $summary.Add("apk_bytes=$($apk.Length)")
    $summary.Add("apk_sha256=$($hash.Hash.ToLowerInvariant())")
}

$packages = @(
    "org.xiyu.githubdirect",
    "org.lsposed.manager",
    "me.weishu.kernelsu",
    "com.topjohnwu.magisk",
    "com.github.android",
    "com.android.chrome",
    "com.brave.browser",
    "org.mozilla.firefox",
    "com.microsoft.emmx"
)
foreach ($package in $packages) {
    Save-Lines -Name "package-$package.txt" -Action {
        $packagePaths = try {
            @(Invoke-Adb -Arguments @("shell", "pm", "path", $package))
        } catch {
            @()
        }
        @($packagePaths) + @(Invoke-Adb -Arguments @("shell", "dumpsys", "package", $package))
    } -Filter {
        param($lines)
        $selected = @($lines | Where-Object {
            $_ -match '^package:|Package \[|codePath=|versionName=|versionCode=|userId=|firstInstallTime=|lastUpdateTime='
        })
        if ($selected.Count -eq 0) { "<not installed or package metadata unavailable>" } else { $selected }
    }
}

Save-Lines -Name "installed-apk-org.xiyu.githubdirect.txt" -Action {
    $result = [System.Collections.Generic.List[string]]::new()
    $paths = @(Invoke-Adb -Arguments @("shell", "pm", "path", "org.xiyu.githubdirect"))
    if ($paths.Count -eq 0) {
        $result.Add("<module package is not installed>")
    }
    foreach ($line in $paths) {
        $text = ([string]$line).Trim()
        if ($text -notmatch '^package:(/[A-Za-z0-9_./+=~-]+\.apk)$') {
            $result.Add("REJECTED_UNSAFE_PATH: $text")
            continue
        }
        $deviceApkPath = $Matches[1]
        $result.Add("path=$deviceApkPath")
        try {
            $deviceHash = @(Invoke-Root -Command "sha256sum '$deviceApkPath'")
            foreach ($hashLine in $deviceHash) {
                $result.Add("sha256sum=$hashLine")
            }
        } catch {
            $message = $_.Exception.Message
            $result.Add("sha256sum=ERROR: $message")
            $script:collectionErrors.Add("installed APK hash: $message")
        }
    }
    $result.ToArray()
}

Save-Lines -Name "root-version.txt" -Action {
    @(Get-CapturedSection -Label "su -v" -Action {
        Invoke-Adb -Arguments @("shell", "su", "-v")
    }) + @(Get-CapturedSection -Label "su -V" -Action {
        Invoke-Adb -Arguments @("shell", "su", "-V")
    })
}

Save-Lines -Name "root-capabilities.txt" -Action {
    @(Get-CapturedSection -Label "root id" -Action {
        Invoke-Root -Command "id"
    }) + @(Get-CapturedSection -Label "iptables --version" -Action {
        Invoke-Root -Command "iptables --version"
    }) + @(Get-CapturedSection -Label "ip6tables --version" -Action {
        Invoke-Root -Command "ip6tables --version"
    }) + @(Get-CapturedSection -Label "ipset --version" -Action {
        Invoke-Root -Command "ipset --version"
    }) + @(Get-CapturedSection -Label "SELinux" -Action {
        Invoke-Adb -Arguments @("shell", "getenforce")
    }) + @(Get-CapturedSection -Label "page size" -Action {
        Invoke-Adb -Arguments @("shell", "getconf", "PAGESIZE")
    })
}

Save-Lines -Name "private-dns-and-proxy.txt" -Action {
    @(Get-CapturedSection -Label "private_dns_mode" -Action {
        Invoke-Adb -Arguments @("shell", "settings", "get", "global", "private_dns_mode")
    }) + @(Get-CapturedSection -Label "private_dns_specifier" -Action {
        Invoke-Adb -Arguments @("shell", "settings", "get", "global", "private_dns_specifier")
    }) + @(Get-CapturedSection -Label "http_proxy" -Action {
        Invoke-Adb -Arguments @("shell", "settings", "get", "global", "http_proxy")
    })
}

Save-Lines -Name "root-service.txt" -Action {
    Invoke-Adb -Arguments @("shell", "dumpsys", "activity", "services", "org.xiyu.githubdirect")
}

Save-Lines -Name "processes.txt" -Action {
    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($package in $packages) {
        $result.Add("[$package]")
        try {
            $pids = @(Invoke-Adb -Arguments @("shell", "pidof", $package))
            if ($pids.Count -eq 0 -or [string]::IsNullOrWhiteSpace(($pids -join ""))) {
                $result.Add("<not running>")
            } else {
                foreach ($pidLine in $pids) { $result.Add([string]$pidLine) }
            }
        } catch {
            $result.Add("<not running or pidof unavailable>")
        }
        $result.Add("")
    }
    $result.ToArray()
}

Save-Lines -Name "listeners.txt" -Action {
    Invoke-Root -Command "ss -lntup"
} -Filter {
    param($lines)
    $selected = @($lines | Where-Object {
        $keep = $false
        foreach ($match in [regex]::Matches([string]$_, ':(\d{1,5})(?=\s|$)')) {
            $port = [int]$match.Groups[1].Value
            if ($port -in @(5354, 5355, 7443) -or $port -in 7010..7254) {
                $keep = $true
                break
            }
        }
        $keep
    })
    if ($selected.Count -eq 0) { "<no GitHub-direct listener ports found>" } else { $selected }
}

Save-Lines -Name "iptables-ghd.txt" -Action {
    @(Invoke-Root -Command "iptables -t nat -S") + @(Invoke-Root -Command "iptables -t filter -S")
} -Filter { param($lines) $lines | Where-Object { $_ -match 'GHD_' } }

Save-Lines -Name "ip6tables-ghd.txt" -Action {
    @(Invoke-Root -Command "ip6tables -t nat -S") + @(Invoke-Root -Command "ip6tables -t filter -S")
} -Filter { param($lines) $lines | Where-Object { $_ -match 'GHD_' } }

Save-Lines -Name "iptables-ghd-counters.txt" -Action {
    Invoke-Root -Command "iptables-save -c"
} -Filter { param($lines) $lines | Where-Object { $_ -match 'GHD_' } }

Save-Lines -Name "ip6tables-ghd-counters.txt" -Action {
    Invoke-Root -Command "ip6tables-save -c"
} -Filter { param($lines) $lines | Where-Object { $_ -match 'GHD_' } }

Save-Lines -Name "ipset-ghd.txt" -Action {
    Invoke-Root -Command "ipset save"
} -Filter { param($lines) $lines | Where-Object { $_ -match 'GHD_' } }

Save-Lines -Name "root-relay-status.xml" -Action {
    try {
        Invoke-Root -Command "cat /data/user/0/org.xiyu.githubdirect/shared_prefs/root_relay_status.xml"
    } catch {
        "<not initialized or unavailable: $($_.Exception.Message)>"
    }
}

foreach ($package in @("org.xiyu.githubdirect", "com.github.android", "com.android.chrome", "com.brave.browser", "org.mozilla.firefox", "com.microsoft.emmx")) {
    Save-Lines -Name "exit-info-$package.txt" -Action {
        Invoke-Adb -Arguments @("shell", "dumpsys", "activity", "exit-info", $package)
    } -Filter {
        param($lines)
        $selected = @($lines | Where-Object {
            $_ -match 'ApplicationExitInfo|processName=|packageUid=|definingUid=|reason=|REASON_|status=|importance=|pss=|rss=|timestamp=|description=|traceFile='
        })
        if ($selected.Count -eq 0) { "<no matching exit records>" } else { $selected }
    }
}

Save-Lines -Name "github-direct-logcat.txt" -Action {
    Invoke-Adb -Arguments @("logcat", "-d", "-v", "threadtime")
} -Filter {
    param($lines)
    $lines | Where-Object { $_ -match 'GithubDirect|RootRelayService|GithubRoutes|GHD-' }
}

$summary.Add("collection_error_count=$($collectionErrors.Count)")
$summary | Set-Content -LiteralPath (Join-Path $OutputDirectory "device-summary.txt") -Encoding utf8

$errorFile = Join-Path $OutputDirectory "collection-errors.txt"
if ($collectionErrors.Count -eq 0) {
    "none" | Set-Content -LiteralPath $errorFile -Encoding utf8
} else {
    $collectionErrors | Sort-Object -Unique | Set-Content -LiteralPath $errorFile -Encoding utf8
}

$manifestPath = Join-Path $OutputDirectory "evidence-manifest.sha256"
$manifest = Get-ChildItem -LiteralPath $OutputDirectory -File |
    Where-Object { $_.Name -ne "evidence-manifest.sha256" } |
    Sort-Object Name |
    ForEach-Object {
        $fileHash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$fileHash  $($_.Name)"
    }
$manifest | Set-Content -LiteralPath $manifestPath -Encoding utf8

Write-Output "Evidence collected at: $OutputDirectory"
Write-Output "Collection command failures: $($collectionErrors.Count) (see collection-errors.txt)"
Write-Output "This script only collects evidence; complete the manual app/browser checks in docs/VALIDATION.md."
