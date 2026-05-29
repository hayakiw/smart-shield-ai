# NSSM が使えない環境向け: Windows Task Scheduler で「起動時に実行・落ちたら再起動」を登録する
# 管理者 PowerShell で実行すること

[CmdletBinding()]
param(
    [string]$TaskName    = "SmartShield",
    [string]$AppRoot     = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [string]$Python      = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path ".venv\Scripts\python.exe"),
    [string]$ConfigPath  = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path "config\shield.yaml"),
    [string]$RunAsUser   = "SYSTEM"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Python))      { throw "python.exe が見つかりません: $Python" }
if (-not (Test-Path $ConfigPath))  { throw "config が見つかりません: $ConfigPath" }

$Action = New-ScheduledTaskAction `
    -Execute $Python `
    -Argument "-m shield -c `"$ConfigPath`" run" `
    -WorkingDirectory $AppRoot

$Trigger = New-ScheduledTaskTrigger -AtStartup

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 0)   # 0 = 無制限

$Principal = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Principal $Principal `
    -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName
Get-ScheduledTask -TaskName $TaskName | Format-Table TaskName, State -AutoSize

Write-Host ""
Write-Host "停止:    Stop-ScheduledTask  -TaskName $TaskName"
Write-Host "状態:    Get-ScheduledTask   -TaskName $TaskName | Get-ScheduledTaskInfo"
Write-Host "削除:    Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"
Write-Host ""
Write-Host "注: Task Scheduler はサービスマネージャほど厳格ではないため、本番運用は NSSM 経由を推奨。"
