<#
  setup-elevated-collect.ps1 -- run the Hearth collector elevated, at logon.

  Why: four host-posture checks (audit policy, the Security event log, the
  Security-log-cleared event, Defender's exclusion list) cannot be read without
  Administrator. Run unprivileged they come back "could not run" -- honestly
  unmeasured, never falsely passing. This registers a Scheduled Task that runs
  the COLLECTOR at logon with highest privileges so those checks -- and the
  auth-anomaly detections that depend on the Security log -- can run.

  Only the collector is elevated. The dashboard (`serve`, network-facing) stays
  unprivileged, started from the Startup folder by start-pnma.ps1: least
  privilege for the half that listens on a socket.

  Registering a highest-privilege task itself needs Administrator, so this
  script relaunches itself elevated (one UAC prompt). Re-runnable; pass
  -Remove to undo.
#>
param([switch]$Remove)

$ErrorActionPreference = 'Stop'
$TaskName = 'Hearth collector (elevated)'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# Relaunch elevated if we are not already Administrator.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Remove) { $args += '-Remove' }
    Start-Process powershell -Verb RunAs -ArgumentList $args
    return
}

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task '$TaskName'. The Startup script still runs the collector unprivileged."
    return
}

# Find python (prefer the one on PATH; fall back to the known install).
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { $python = 'C:\Python314\python.exe' }

New-Item -ItemType Directory -Force -Path "$root\logs" | Out-Null

# The action logs to the same files the Startup script used, appending, so the
# operator has one place to look regardless of which half started collection.
$cmd = "cd /d `"$root`" && `"$python`" -m pnma collect >> `"$root\logs\collect.log`" 2>> `"$root\logs\collect.err.log`""
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $cmd"

# The current user, at their logon, with the highest privileges their account
# can obtain (this is what lets the Security-log checks read).
$user = "$env:USERDOMAIN\$env:USERNAME"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -Hidden `
            -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force `
    -Description 'Runs the Hearth network collector at logon with elevation so the admin-gated host checks can read.' | Out-Null

Write-Host "Registered scheduled task '$TaskName' (runs at logon, elevated)."

# Stop any unprivileged collector and start the elevated one now, so the change
# takes effect without waiting for the next logon.
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -match 'pnma collect' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName $TaskName
Write-Host "Started the elevated collector now. Give it a minute, then the four admin checks on the Host tab will read."
