param(
    [string]$Prefix = "$env:USERPROFILE\.entanglement"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$BinDir = Join-Path $Prefix "bin"

Push-Location $Root
try {
    cargo build --release -p ent-cli
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    Copy-Item (Join-Path $Root "target\release\entc.exe") (Join-Path $BinDir "entc.exe") -Force
    Write-Host "installed entc to $(Join-Path $BinDir 'entc.exe')"
    Write-Host "run: entc doctor"
} finally {
    Pop-Location
}
