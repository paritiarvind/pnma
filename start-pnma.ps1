<#
  start-pnma.ps1 -- start the collector and the dashboard, detached.

  Meant for a shortcut in the per-user Startup folder (shell:startup), so both
  halves come back after a reboot without a scheduled task or a service, and
  without elevation. Each half is started only if it is not already running,
  so running this twice is harmless. Logs go to logs/.

  The dashboard binds to the tailnet (see README, "From your phone,
  privately"); if Tailscale is not signed in it exits with a clear message
  and the collector keeps running on its own.
#>
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
New-Item -ItemType Directory -Force -Path "$root\logs" | Out-Null

$running = Get-CimInstance Win32_Process -Filter "name='python.exe'" | Select-Object -ExpandProperty CommandLine
if (-not ($running -match 'pnma collect')) {
    Start-Process -WindowStyle Hidden -FilePath python -ArgumentList '-m','pnma','collect' `
        -RedirectStandardOutput "$root\logs\collect.log" -RedirectStandardError "$root\logs\collect.err.log"
}
if (-not ($running -match 'pnma serve')) {
    Start-Process -WindowStyle Hidden -FilePath python -ArgumentList '-m','pnma','serve','--bind','tailscale' `
        -RedirectStandardOutput "$root\logs\serve.log" -RedirectStandardError "$root\logs\serve.err.log"
}
