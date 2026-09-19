<#
    harden-host.ps1 -- enable host security telemetry on this host
    Run from an ELEVATED PowerShell prompt:  powershell -ExecutionPolicy Bypass -File .\harden-host.ps1

    Every change is reversible; -Rollback undoes all of it.
    Nothing here installs an agent or sends data anywhere. It turns on logging
    that Windows already ships with, and sizes the logs so they are actually useful.

    NOT done by this script (cannot be):
      * Tamper Protection  -- Microsoft deliberately blocks scripted enablement.
                              Windows Security > Virus & threat protection >
                              Manage settings > Tamper Protection > On
      * Sysmon             -- needs a download; see the Sysmon section at the bottom.
#>

[CmdletBinding()]
param(
    [switch]$Rollback,
    [switch]$SkipFullScan,
    [string]$TranscriptPath = 'C:\ProgramData\PSTranscripts'
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must run elevated. Right-click PowerShell > Run as administrator." -ForegroundColor Red
    exit 1
}

$PSBase     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$AuditKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'

function Set-RegValue {
    param($Path, $Name, $Value, $Type = 'DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-Host "  set  $Path\$Name = $Value" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- ROLLBACK ---

if ($Rollback) {
    Write-Host "`n=== ROLLING BACK ===`n" -ForegroundColor Yellow
    foreach ($k in 'ScriptBlockLogging','ModuleLogging','Transcription') {
        if (Test-Path "$PSBase\$k") { Remove-Item "$PSBase\$k" -Recurse -Force; Write-Host "  removed $k" }
    }
    Remove-ItemProperty -Path $AuditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Force -ErrorAction SilentlyContinue
    foreach ($sub in 'Process Creation','Logon','Logoff','Special Logon','Other Logon/Logoff Events') {
        auditpol /set /subcategory:"$sub" /success:disable /failure:disable | Out-Null
    }
    Write-Host "`nRolled back. Log size changes and the Defender scan are left as-is." -ForegroundColor Green
    exit 0
}

Write-Host "`n=== 1. Event log sizing ===" -ForegroundColor Cyan
Write-Host "Doing this FIRST. Turning on verbose logging without resizing the logs" -ForegroundColor DarkGray
Write-Host "just makes them roll over faster -- you would end up with LESS history." -ForegroundColor DarkGray

# Security: 20 MB default holds only hours once 4688 is on. 1 GB ~= weeks.
wevtutil sl Security /ms:1073741824
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:536870912
wevtutil sl System /ms:134217728
Write-Host "  Security   -> 1 GB"
Write-Host "  PowerShell -> 512 MB"
Write-Host "  System     -> 128 MB"

Write-Host "`n=== 2. Process creation auditing (4688) + command line ===" -ForegroundColor Cyan
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
Set-RegValue -Path $AuditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
Write-Host "  4688 now records the full command line of every process started."

Write-Host "`n=== 3. Logon auditing (4624 / 4625) ===" -ForegroundColor Cyan
foreach ($sub in 'Logon','Logoff','Special Logon','Other Logon/Logoff Events') {
    auditpol /set /subcategory:"$sub" /success:enable /failure:enable | Out-Null
    Write-Host "  enabled: $sub (success + failure)"
}
# Account lockout / credential validation -- cheap and high value
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
Write-Host "  enabled: Credential Validation (success + failure)"

Write-Host "`n=== 4. PowerShell script block logging (4104) ===" -ForegroundColor Cyan
Set-RegValue -Path "$PSBase\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1
# NOTE: EnableScriptBlockInvocationLogging is deliberately NOT set -- it multiplies
# volume by 10x or more for very little extra detection value.
Write-Host "  Deobfuscated script text is now recorded. This is the single most"
Write-Host "  valuable PowerShell control -- it defeats base64/obfuscated payloads."

Write-Host "`n=== 5. PowerShell module logging (4103) ===" -ForegroundColor Cyan
Set-RegValue -Path "$PSBase\ModuleLogging" -Name 'EnableModuleLogging' -Value 1
if (-not (Test-Path "$PSBase\ModuleLogging\ModuleNames")) {
    New-Item -Path "$PSBase\ModuleLogging\ModuleNames" -Force | Out-Null
}
New-ItemProperty -Path "$PSBase\ModuleLogging\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null
Write-Host "  set  ModuleNames\* = *" -ForegroundColor DarkGray
Write-Host "  Pipeline execution detail for all modules. Highest-volume item here."

Write-Host "`n=== 6. PowerShell transcription ===" -ForegroundColor Cyan
if (-not (Test-Path $TranscriptPath)) { New-Item -ItemType Directory -Path $TranscriptPath -Force | Out-Null }
# Only SYSTEM and Administrators should be able to read transcripts -- they contain
# command OUTPUT, which is frequently more sensitive than the commands themselves.
icacls $TranscriptPath /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
Set-RegValue -Path "$PSBase\Transcription" -Name 'EnableTranscripting'    -Value 1
Set-RegValue -Path "$PSBase\Transcription" -Name 'EnableInvocationHeader' -Value 1
Set-RegValue -Path "$PSBase\Transcription" -Name 'OutputDirectory' -Value $TranscriptPath -Type String
Write-Host "  Transcripts -> $TranscriptPath (ACL: SYSTEM + Administrators only)"
Write-Host "  These grow on disk and are NOT rotated by Windows. See the notes."

Write-Host "`n=== 7. Defender ===" -ForegroundColor Cyan
Write-Host "Closing the four gaps measured on this host:" -ForegroundColor DarkGray

# PUAProtection was 2 (AUDIT) -- it detected the activation script and did nothing.
Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
Write-Host "  PUA protection      : Audit -> Enabled (now blocks, not just observes)"

# DisableRemovableDriveScanning was True -- USB media was never scanned.
Set-MpPreference -DisableRemovableDriveScanning $false -ErrorAction SilentlyContinue
Write-Host "  Removable drives    : now scanned"

# EnableNetworkProtection was 0.
Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
Write-Host "  Network protection  : Enabled (blocks known-malicious domains/IPs)"

Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
Write-Host "  Cloud protection    : Advanced, safe samples"

Write-Host ""
Write-Host "  NOTE: enabling PUA protection will very likely flag the MAS activation" -ForegroundColor Yellow
Write-Host "  script if it is still present. That is correct behaviour, not a false" -ForegroundColor Yellow
Write-Host "  positive. Run .\remove-kms.ps1 -Apply first if you intend to remove it." -ForegroundColor Yellow

Write-Host "`n=== 7b. The checks that need elevation (unanswered until now) ===" -ForegroundColor Cyan

Write-Host "-- Defender exclusions (unreadable non-elevated; the one place a carve-out hides) --"
$mp = Get-MpPreference
foreach ($n in 'ExclusionPath','ExclusionProcess','ExclusionExtension','ExclusionIpAddress') {
    $v = $mp.$n
    if ($v) { Write-Host "  $n :" -ForegroundColor Yellow; $v | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow } }
    else    { Write-Host "  $n : (none)" -ForegroundColor Green }
}

Write-Host "`n-- Security log: was it ever cleared? (Event 1102 / ATT&CK T1070.001) --"
try {
    $c = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction Stop
    Write-Host "  *** $($c.Count) CLEAR EVENT(S) FOUND ***" -ForegroundColor Red
    $c | Select-Object TimeCreated,@{n='Who';e={($_.Message -split "`n" | Select-String 'Account Name') -join ' '}} |
        Format-Table -AutoSize | Out-String | Write-Host
} catch {
    if ($_.Exception -is [System.UnauthorizedAccessException]) { Write-Host "  still not readable -- are you really elevated?" -ForegroundColor Red }
    else { Write-Host "  No 1102 events. The Security log has not been cleared." -ForegroundColor Green }
}
$sec = Get-WinEvent -ListLog Security
Write-Host "  Security log: $($sec.RecordCount) records, $([math]::Round($sec.FileSize/1MB,1)) MB used of $([math]::Round($sec.MaximumSizeInBytes/1MB,0)) MB"

if (-not $SkipFullScan) {
    Write-Host "  Starting full scan in the background (hours, high CPU/disk)..." -ForegroundColor Yellow
    Start-Job -Name 'DefenderFullScan' -ScriptBlock { Start-MpScan -ScanType FullScan } | Out-Null
    Write-Host "  Check with:  Get-MpComputerStatus | Select FullScanAge"
} else {
    Write-Host "  Full scan skipped (-SkipFullScan). Run later: Start-MpScan -ScanType FullScan"
}

Write-Host "`n=== DONE ===" -ForegroundColor Green
Write-Host @"

Still to do by hand:

  1. TAMPER PROTECTION  (cannot be scripted -- by design)
     Windows Security > Virus & threat protection > Manage settings
       > Tamper Protection > On

  2. SYSMON
     Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile `$env:TEMP\Sysmon.zip
     Expand-Archive `$env:TEMP\Sysmon.zip -DestinationPath `$env:TEMP\Sysmon
     # Use a curated config -- the default logs almost nothing useful:
     #   https://github.com/SwiftOnSecurity/sysmon-config
     .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml

Verify everything took:
  auditpol /get /category:* | findstr /i "Process Creation,Logon"
  Get-ItemProperty '$PSBase\ScriptBlockLogging'
  Get-WinEvent -ListLog Security | Select RecordCount, MaximumSizeInBytes

Undo:  .\harden-host.ps1 -Rollback
"@ -ForegroundColor Gray
