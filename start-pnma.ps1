<#
  start-pnma.ps1 -- start the dashboard, detached, after a reboot.

  Meant for a shortcut in the per-user Startup folder (shell:startup). It owns
  the DASHBOARD half only (`serve`), which is network-facing and deliberately
  runs UNPRIVILEGED -- least privilege for the half that listens on a socket.

  The COLLECTOR is owned by the "Hearth collector (elevated)" scheduled task
  (see setup-elevated-collect.ps1): it runs at logon with Administrator so the
  admin-gated host checks (audit policy, the Security event log, Defender
  exclusions) can read. If that task is not registered, this script starts an
  unprivileged collector as a fallback so collection still happens -- those
  four checks will just report "could not run" until the task is set up.

  Each half is started only if not already running, so running this twice is
  harmless. Logs go to logs/.
#>
# pnma-agent
# ^ This marker attributes this script's PowerShell to PNMA itself. Windows
# logs a running .ps1 as a 4104 script block; the collector treats any block
# containing "# pnma-agent" as the agent's own (host_windows.AGENT_MARKER) and
# does not raise suspicious_powershell on it -- exactly as it does for the
# encoded one-liners `_ps` runs. Without this, PNMA's own collector-management
# here (Get-CimInstance ... 'pnma collect', Get-ScheduledTask) reads as a
# suspicious encoded/process-hunting block. Keep the marker verbatim.
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
New-Item -ItemType Directory -Force -Path "$root\logs" | Out-Null

$running = Get-CimInstance Win32_Process -Filter "name='python.exe'" | Select-Object -ExpandProperty CommandLine

# The elevated scheduled task owns the collector. Only fall back to an
# unprivileged collector here if that task does not exist AND none is running.
$task = Get-ScheduledTask -TaskName 'Hearth collector (elevated)' -ErrorAction SilentlyContinue
if (-not $task -and -not ($running -match 'pnma collect')) {
    Start-Process -WindowStyle Hidden -FilePath python -ArgumentList '-m','pnma','collect' `
        -RedirectStandardOutput "$root\logs\collect.log" -RedirectStandardError "$root\logs\collect.err.log"
}

if (-not ($running -match 'pnma serve')) {
    Start-Process -WindowStyle Hidden -FilePath python -ArgumentList '-m','pnma','serve','--bind','tailscale' `
        -RedirectStandardOutput "$root\logs\serve.log" -RedirectStandardError "$root\logs\serve.err.log"
}
