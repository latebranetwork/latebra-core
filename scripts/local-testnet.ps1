# Latebra — spin up a local multi-node testnet (Windows PowerShell).
#
# Builds the binaries, then starts:
#   - a mining node   on 127.0.0.1:4040
#   - a syncing node  on 127.0.0.1:4041  (peers with the miner)
#   - the explorer    on http://127.0.0.1:8080
#
# Data is written under a temp folder so re-running starts fresh.
# Use ./scripts/local-testnet.ps1 -Stop to shut it all down.

param([switch]$Stop)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

if ($Stop) {
    Get-Process latebrad, lat-explorer, lat-wallet-web -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "Stopped all latebrad, lat-explorer and lat-wallet-web processes."
    return
}

Write-Host "Building release binaries..." -ForegroundColor Cyan
cargo build --release -q -p latebrad -p lat-explorer -p lat-wallet-cli -p lat-wallet-web
$rel = Join-Path $root "target/release"

# Fresh data dirs.
$data = Join-Path $env:TEMP ("latebra-testnet-" + (Get-Random))
New-Item -ItemType Directory -Force -Path $data | Out-Null

Write-Host "Starting mining node on 127.0.0.1:4040..." -ForegroundColor Cyan
$miner = Start-Process "$rel/latebrad.exe" `
    -ArgumentList "--mine", "--data", "$data/a/chain.db", "--listen", "127.0.0.1:4040" `
    -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 2

Write-Host "Starting syncing node on 127.0.0.1:4041 (peer of the miner)..." -ForegroundColor Cyan
$peer = Start-Process "$rel/latebrad.exe" `
    -ArgumentList "--data", "$data/b/chain.db", "--listen", "127.0.0.1:4041", "--peer", "127.0.0.1:4040" `
    -PassThru -WindowStyle Hidden

Write-Host "Starting explorer on http://127.0.0.1:8080..." -ForegroundColor Cyan
$exp = Start-Process "$rel/lat-explorer.exe" `
    -ArgumentList "--testnet", "127.0.0.1:4040", "--listen", "127.0.0.1:8080" `
    -PassThru -WindowStyle Hidden

Write-Host "Starting web wallet on http://127.0.0.1:8090..." -ForegroundColor Cyan
$wal = Start-Process "$rel/lat-wallet-web.exe" `
    -ArgumentList "--listen", "127.0.0.1:8090" `
    -PassThru -WindowStyle Hidden

Write-Host ""
Write-Host "Local testnet is running." -ForegroundColor Green
Write-Host "  Explorer  : http://127.0.0.1:8080"
Write-Host "  Web wallet: http://127.0.0.1:8090"
Write-Host "  Miner RPC : 127.0.0.1:4040     (PID $($miner.Id))"
Write-Host "  Peer RPC  : 127.0.0.1:4041     (PID $($peer.Id))"
Write-Host ""
Write-Host "Open the web wallet, click 'Create new wallet', then get testnet coins" -ForegroundColor Yellow
Write-Host "from the genesis faucet with the CLI:" -ForegroundColor Yellow
Write-Host "  $rel\lat-wallet.exe send --seed $('2a'*32) --to <your-address> --amount 100 --node 127.0.0.1:4040"
Write-Host ""
Write-Host "Stop everything with:  ./scripts/local-testnet.ps1 -Stop" -ForegroundColor Yellow
