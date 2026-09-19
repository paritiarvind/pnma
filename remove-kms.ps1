<#
    remove-kms.ps1 -- remove the MAS / K-M-S activation persistence from this host
    Run ELEVATED:  powershell -ExecutionPolicy Bypass -File .\remove-kms.ps1

    Default is a DRY RUN. Nothing is changed until you pass -Apply.

    What this removes
      1. Scheduled tasks  \Activation-Renewal  and  \Activation-Run_Once
      2. C:\Program Files\Activation-Renewal\   (script, Info.txt, Logs.txt)
      3. The pinned third-party K-M-S host in the registry -- the part that
         actually matters, and the part people forget. Leaving it behind means
         Office keeps trying to reach 140.238.60.128 (kms.wxlost.com) forever.

    Consequences, measured on this host 2026-08-24
      * Office 16 (Office16MondoVL_KMS_Client) is Licensed with ~179.5 days
        remaining. It will run normally until roughly 2027-02-19, then drop
        into reduced-functionality mode unless licensed another way.
      * WINDOWS IS UNAFFECTED. It is OEM_DM channel -- a genuine OEM licence.
        MAS was never activating Windows on this machine.
#>

[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$KeepLogs          # preserve Logs.txt as evidence before deleting the folder
)

$ErrorActionPreference = 'Stop'
$EvidenceDir = Join-Path $PSScriptRoot 'kms-evidence'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Must run elevated." -ForegroundColor Red; exit 1
}

$mode = if ($Apply) { "APPLY" } else { "DRY RUN -- pass -Apply to make changes" }
Write-Host "`n=== KMS removal : $mode ===`n" -ForegroundColor Cyan

function Do-Step {
    param([string]$Desc, [scriptblock]$Action)
    if ($Apply) {
        try { & $Action; Write-Host "  [done] $Desc" -ForegroundColor Green }
        catch { Write-Host "  [FAIL] $Desc -- $($_.Exception.Message)" -ForegroundColor Red }
    } else {
        Write-Host "  [would] $Desc" -ForegroundColor Yellow
    }
}

# --- 0. Preserve evidence first --------------------------------------------

Write-Host "-- 0. Evidence capture --"
if ($Apply) {
    New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
    foreach ($f in 'Activation_task.cmd','Info.txt','Logs.txt') {
        $src = "C:\Program Files\Activation-Renewal\$f"
        if (Test-Path $src) {
            Copy-Item $src (Join-Path $EvidenceDir $f) -Force
            $h = (Get-FileHash $src -Algorithm SHA256).Hash
            "$f  SHA256=$h" | Add-Content (Join-Path $EvidenceDir 'hashes.txt')
        }
    }
    # snapshot the task definition and the registry state before touching them
    # /xml takes no ONE|ALL argument when /tn is given -- "/xml ALL" errors with
    # "Improper display format type specified."
    schtasks /query /tn "Activation-Renewal" /xml 2>$null | Out-File (Join-Path $EvidenceDir 'Activation-Renewal.xml') -Encoding utf8
    Write-Host "  [done] evidence -> $EvidenceDir" -ForegroundColor Green
} else {
    Write-Host "  [would] copy script + logs + task XML + hashes to $EvidenceDir" -ForegroundColor Yellow
}

# --- 1. Scheduled tasks -----------------------------------------------------

Write-Host "`n-- 1. Scheduled tasks --"
foreach ($t in 'Activation-Renewal','Activation-Run_Once') {
    $exists = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if ($exists) {
        Do-Step "delete scheduled task \$t" { Unregister-ScheduledTask -TaskName $t -Confirm:$false }
    } else {
        Write-Host "  [skip] \$t not present" -ForegroundColor DarkGray
    }
}

# --- 2. Files ---------------------------------------------------------------

Write-Host "`n-- 2. Files --"
$dir = 'C:\Program Files\Activation-Renewal'
if (Test-Path $dir) {
    if ($KeepLogs -and $Apply) {
        Copy-Item "$dir\Logs.txt" (Join-Path $EvidenceDir 'Logs.retained.txt') -Force -ErrorAction SilentlyContinue
    }
    Do-Step "remove $dir" { Remove-Item $dir -Recurse -Force }
} else {
    Write-Host "  [skip] $dir not present" -ForegroundColor DarkGray
}

# --- 3. Registry: the part that actually persists ---------------------------

Write-Host "`n-- 3. Registry (pinned K-M-S host) --"

$SPP  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
$SPP32= 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
$OPP  = 'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform'
$SVC  = 'Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'

$values = 'KeyManagementServiceName','KeyManagementServicePort',
          'DisableDnsPublishing','DisableKeyManagementServiceHostCaching'

foreach ($root in @($SPP,$SPP32,$OPP,$SVC)) {
    if (-not (Test-Path $root)) { continue }

    foreach ($v in $values) {
        $cur = (Get-ItemProperty -Path $root -Name $v -ErrorAction SilentlyContinue).$v
        if ($null -ne $cur) {
            Do-Step "$root -> remove $v (currently '$cur')" {
                Remove-ItemProperty -Path $root -Name $v -Force
            }
        }
    }

    # per-application subkeys (Windows GUID and the Office GUID 0ff1ce15-...)
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $sub = $_.PSPath
        foreach ($v in $values) {
            $cur = (Get-ItemProperty -Path $sub -Name $v -ErrorAction SilentlyContinue).$v
            if ($null -ne $cur) {
                $short = $_.PSChildName
                Do-Step "$short -> remove $v (currently '$cur')" {
                    Remove-ItemProperty -Path $sub -Name $v -Force
                }
            }
        }
    }
}

# --- 4. Restart the licensing service so it re-reads config -----------------

Write-Host "`n-- 4. Software Protection service --"
Do-Step "restart sppsvc so it drops the cached K-M-S host" {
    Stop-Service sppsvc -Force -ErrorAction SilentlyContinue
    Start-Service sppsvc -ErrorAction SilentlyContinue
}

# --- 5. Verify --------------------------------------------------------------

Write-Host "`n-- 5. Verification --"
$remaining = @()
foreach ($root in @($SPP,$SPP32,$OPP,$SVC)) {
    if (-not (Test-Path $root)) { continue }
    $v = (Get-ItemProperty -Path $root -Name 'KeyManagementServiceName' -ErrorAction SilentlyContinue).KeyManagementServiceName
    if ($v) { $remaining += "$root = $v" }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $sv = (Get-ItemProperty -Path $_.PSPath -Name 'KeyManagementServiceName' -ErrorAction SilentlyContinue).KeyManagementServiceName
        if ($sv) { $remaining += "$($_.PSChildName) = $sv" }
    }
}

if ($remaining) {
    Write-Host "  K-M-S host still pinned in:" -ForegroundColor Yellow
    $remaining | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
} else {
    Write-Host "  No K-M-S host pinned anywhere." -ForegroundColor Green
}

Write-Host "`n  Task present : $([bool](Get-ScheduledTask -TaskName 'Activation-Renewal' -ErrorAction SilentlyContinue))"
Write-Host "  Folder present: $(Test-Path 'C:\Program Files\Activation-Renewal')"
Write-Host "`n  Office licence state:"
Get-CimInstance SoftwareLicensingProduct -ErrorAction SilentlyContinue |
    Where-Object { $_.PartialProductKey -and $_.Name -match 'Office' } |
    Select-Object Name,
        @{n='Status';e={switch($_.LicenseStatus){0{'Unlicensed'}1{'Licensed'}2{'OOBGrace'}3{'OOTGrace'}4{'NonGenuineGrace'}5{'Notification'}6{'ExtGrace'}}}},
        @{n='DaysLeft';e={[math]::Round($_.GracePeriodRemaining/1440,1)}},
        @{n='KMSHost';e={$_.KeyManagementServiceMachine}} |
    Format-List | Out-String | Write-Host

if (-not $Apply) { Write-Host "`nDRY RUN -- nothing changed. Re-run with -Apply.`n" -ForegroundColor Cyan }
