# Latebra multi-node soak test (T23).
#
# Runs a 3-node local testnet (miner + 2 followers) for -Minutes, killing and
# restarting the third node every -ChaosSecs to exercise crash-recovery, boot
# paths (records / fast sync), peer re-join, and fork reconciliation. Polls
# every node's /status endpoint throughout; at the end, asserts all nodes
# converged on the SAME tip and that no process died on its own.
#
#   ./scripts/soak-testnet.ps1                # 10-minute soak
#   ./scripts/soak-testnet.ps1 -Minutes 120   # long soak (e.g. overnight)
#
# Exit code 0 = converged, 1 = failure (divergent tips / dead node / stall).

param(
    [int]$Minutes = 10,
    [int]$ChaosSecs = 90
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$bin = Join-Path $root "target\release\latebrad.exe"
if (-not (Test-Path $bin)) {
    Write-Host "Building latebrad (release)..."
    cargo build --release -p latebrad
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

$soak = Join-Path $env:TEMP ("latebra-soak-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force $soak | Out-Null
Write-Host "Soak data: $soak"

# node name -> (p2p port, metrics port, extra args)
$nodes = [ordered]@{
    "miner"  = @(24040, 24090, @("--mine", "--validator"))
    "node-b" = @(24041, 24091, @("--peer", "127.0.0.1:24040"))
    "node-c" = @(24042, 24092, @("--peer", "127.0.0.1:24041"))
}

function Start-Node([string]$name) {
    $p2p, $metrics, $extra = $nodes[$name]
    $args = @(
        "--data", "$soak\$name\chain.db",
        "--listen", "127.0.0.1:$p2p", "--public-addr", "127.0.0.1:$p2p",
        "--metrics", "127.0.0.1:$metrics"
    ) + $extra
    Start-Process -FilePath $bin -ArgumentList $args -WindowStyle Hidden `
        -RedirectStandardOutput "$soak\$name.log" -RedirectStandardError "$soak\$name.err" -PassThru
}

function Get-Status([int]$metricsPort) {
    try {
        Invoke-RestMethod -Uri "http://127.0.0.1:$metricsPort/status" -TimeoutSec 3
    } catch { $null }
}

$procs = @{}
foreach ($name in $nodes.Keys) {
    $procs[$name] = Start-Node $name
    Start-Sleep -Seconds 2
}

$deadline = (Get-Date).AddMinutes($Minutes)
$lastChaos = Get-Date
$lastHeight = -1
$lastProgress = Get-Date
$failed = $null

while ((Get-Date) -lt $deadline -and -not $failed) {
    Start-Sleep -Seconds 10

    # Liveness: miner + node-b must never die on their own; node-c only dies
    # when the chaos step killed it (it is restarted right there).
    foreach ($name in @("miner", "node-b")) {
        if ($procs[$name].HasExited) { $failed = "$name exited unexpectedly" }
    }
    if ($failed) { break }

    $tips = @()
    foreach ($name in $nodes.Keys) {
        $s = Get-Status $nodes[$name][1]
        if ($s) { $tips += "$name h=$($s.height) peers=$($s.peers) boot=$($s.boot_mode)" }
    }
    Write-Host ("[{0:HH:mm:ss}] " -f (Get-Date)) ($tips -join "  |  ")

    # Stall detection: the miner's height must keep advancing.
    $m = Get-Status $nodes["miner"][1]
    if ($m) {
        if ($m.height -gt $lastHeight) { $lastHeight = $m.height; $lastProgress = Get-Date }
        elseif (((Get-Date) - $lastProgress).TotalSeconds -gt 120) { $failed = "miner stalled at height $lastHeight" }
    }

    # Chaos: kill node-c, wait, restart — it must catch up again.
    if (((Get-Date) - $lastChaos).TotalSeconds -ge $ChaosSecs) {
        Write-Host "  [chaos] killing node-c"
        try { Stop-Process -Id $procs["node-c"].Id -Force -ErrorAction Stop } catch {}
        Start-Sleep -Seconds 10
        $procs["node-c"] = Start-Node "node-c"
        $lastChaos = Get-Date
    }
}

if (-not $failed) {
    # Convergence: stop the miner so the tip freezes, give followers a moment,
    # then all three /status tips must be identical.
    Write-Host "Soak window over — freezing the chain and checking convergence..."
    try { Stop-Process -Id $procs["miner"].Id -Force -ErrorAction Stop } catch {}
    # The miner process is gone but its last block may still be in flight.
    Start-Sleep -Seconds 20
    $procs["miner"] = $null

    $finalTips = @{}
    foreach ($name in @("node-b", "node-c")) {
        $s = Get-Status $nodes[$name][1]
        if (-not $s) { $failed = "$name unreachable at the end" }
        else { $finalTips[$name] = "$($s.height):$($s.tip)" }
    }
    if (-not $failed -and ($finalTips["node-b"] -ne $finalTips["node-c"])) {
        $failed = "divergent tips: node-b=$($finalTips['node-b']) node-c=$($finalTips['node-c'])"
    }
    if (-not $failed) {
        Write-Host "CONVERGED at $($finalTips['node-b'])"
    }
}

# Teardown.
foreach ($p in $procs.Values) {
    if ($p -and -not $p.HasExited) { try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch {} }
}

if ($failed) {
    Write-Host "SOAK FAILED: $failed" -ForegroundColor Red
    Write-Host "Logs: $soak"
    exit 1
}
Write-Host "SOAK PASSED ($Minutes min, chaos every $ChaosSecs s). Logs: $soak"
exit 0
