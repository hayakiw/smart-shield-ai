# NSSM (https://nssm.cc/) を使って Windows サービスとして登録する
# 事前に nssm.exe を PATH に通しておくこと
#
# 使い方:
#   PowerShell を「管理者として実行」して
#   .\packaging\windows\install-service-nssm.ps1
#
# 削除:
#   nssm remove SmartShield confirm

[CmdletBinding()]
param(
    [string]$ServiceName = "SmartShield",
    [string]$AppRoot     = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$Python      = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path ".venv\Scripts\python.exe"),
    [string]$ConfigPath  = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path "config\shield.yaml"),
    [string]$LogDir      = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path "var\log"),
    [string]$AnthropicApiKey = $env:ANTHROPIC_API_KEY
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Python)) {
    throw "python.exe が見つかりません: $Python  (先に venv を作って依存をインストールしてください)"
}
if (-not (Test-Path $ConfigPath)) {
    throw "config が見つかりません: $ConfigPath"
}
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    throw "nssm.exe が PATH に無いので入れてください: https://nssm.cc/"
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

Write-Host "Installing service '$ServiceName'..."
nssm install $ServiceName $Python "-m" "shield" "-c" "`"$ConfigPath`"" "run"
nssm set $ServiceName AppDirectory $AppRoot
nssm set $ServiceName DisplayName "Smart Shield (rule + AI log blocker)"
nssm set $ServiceName Description "Regex + AI based log monitor that blocks abusive IPs."
nssm set $ServiceName Start SERVICE_AUTO_START
nssm set $ServiceName AppStdout (Join-Path $LogDir "shield.out.log")
nssm set $ServiceName AppStderr (Join-Path $LogDir "shield.err.log")
nssm set $ServiceName AppRotateFiles 1
nssm set $ServiceName AppRotateBytes 10485760   # 10 MB
nssm set $ServiceName AppExit Default Restart
nssm set $ServiceName AppRestartDelay 5000

if ($AnthropicApiKey) {
    nssm set $ServiceName AppEnvironmentExtra "ANTHROPIC_API_KEY=$AnthropicApiKey" "PYTHONUNBUFFERED=1"
} else {
    nssm set $ServiceName AppEnvironmentExtra "PYTHONUNBUFFERED=1"
    Write-Warning "ANTHROPIC_API_KEY 未設定。AI 機能を使うなら後で 'nssm set $ServiceName AppEnvironmentExtra ANTHROPIC_API_KEY=...' で追加してください。"
}

Write-Host "Starting service..."
Start-Service $ServiceName
Get-Service $ServiceName | Format-Table -AutoSize

Write-Host ""
Write-Host "停止:  Stop-Service $ServiceName"
Write-Host "状態:  Get-Service $ServiceName"
Write-Host "ログ:  Get-Content '$LogDir\shield.out.log' -Wait"
Write-Host "削除:  nssm remove $ServiceName confirm"
