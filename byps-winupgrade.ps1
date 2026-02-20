<#
.SYNOPSIS
    In-place Windows 11 upgrade with pre-checks, bypass for unsupported hardware,
    appraiser blocker detection, ISO mount, and setup monitoring.
.NOTES
    Combines hardware requirement checks, automatic bypass application,
    appraiser XML parsing, and the original upgrade launch/monitor flow.

    Configure behavior in PHASE 0 below.
#>

# Ensure script runs as Administrator
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Run as Administrator." -ForegroundColor Red
    exit 1
}

# ============================================================
# PHASE 0: Configuration
# ============================================================
$config = @{

    # --- Paths ---
    IsoPath              = 'C:\temp\win.iso'

    # --- Thresholds ---
    MinFreeGB            = 24
    MonitorSeconds       = 300

    # --- Bypass Strategy ---
    # "interactive"  = /product server (pops up wizard, user clicks through)
    # "unattended"   = registry key + /Auto Upgrade /Quiet (fully silent, no /product server)
    BypassMode           = 'unattended'

    # --- Bypass Toggles ---
    AutoApplyRegKey      = $true
    WriteSetupConfigIni  = $true

    # --- Setup Arguments (base) ---
    # Used when hardware is fully supported (no bypass needed)
    StandardArgs         = @(
        '/Auto Upgrade',
        '/Quiet',
        '/Eula Accept',
        '/DynamicUpdate Disable',
        '/Compat IgnoreWarning'
    )
}

Write-Host "`n=== PHASE 0: Configuration ===" -ForegroundColor Cyan
Write-Host "INFO: ISO Path:        $($config.IsoPath)"      -ForegroundColor Gray
Write-Host "INFO: Min Free Space:  $($config.MinFreeGB) GB" -ForegroundColor Gray
Write-Host "INFO: Monitor Time:    $($config.MonitorSeconds)s" -ForegroundColor Gray
Write-Host "INFO: Bypass Mode:     $($config.BypassMode)"   -ForegroundColor Gray
Write-Host "INFO: Auto Reg Key:    $($config.AutoApplyRegKey)" -ForegroundColor Gray
Write-Host "INFO: Setup Config:    $($config.WriteSetupConfigIni)" -ForegroundColor Gray

# ============================================================
# PHASE 1: Basic Pre-Checks (Language, AppLocker, Disk Space)
# ============================================================
Write-Host "`n=== PHASE 1: Basic Pre-Checks ===" -ForegroundColor Cyan

# 1.0) OS language check
Write-Host "INFO: Checking system UI language..." -ForegroundColor Cyan
$dismOut = dism.exe /online /get-intl 2>&1
if ($dismOut -match "Default system UI language\s*:\s*en-US") {
    Write-Host "INFO: Language is en-US." -ForegroundColor Green
}
else {
    Write-Host "ERROR: Default system UI language is not en-US." -ForegroundColor Red
    exit 1
}

# 1.1) AppLocker file check
$applockerPath   = 'C:\Windows\System32\AppLocker\exe.applocker'
$applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
Write-Host "INFO: Verifying AppLocker..." -ForegroundColor Cyan
if (Test-Path -Path $applockerPath) {
    Write-Host "ERROR: EXE.AppLocker Found!" -ForegroundColor Red
    if ($applockerPolicy -and ($applockerPolicy.RuleCollections | Where-Object { $_.Rules.Count -gt 0 })) {
        Write-Host "ERROR: AppLocker is configured with rules." -ForegroundColor Red
        Write-Host "ERROR: XML Details: $applockerPolicy" -ForegroundColor Cyan
    }
    else {
        Write-Host "INFO: AppLocker has no configured rules." -ForegroundColor Cyan
        Write-Host "INFO: XML Details: $applockerPolicy" -ForegroundColor Cyan
    }
    exit 1
}
Write-Host "INFO: No EXE.AppLocker file found." -ForegroundColor Green

# 1.2) Free space check
Write-Host "INFO: Checking free space on C:..." -ForegroundColor Cyan
$freeGB = [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2)
if ($freeGB -lt $config.MinFreeGB) {
    Write-Host "ERROR: Only $freeGB GB free (need >=$($config.MinFreeGB) GB)." -ForegroundColor Red
    exit 1
}
Write-Host "INFO: Free space: $freeGB GB." -ForegroundColor Green

# 1.3) ISO file check
Write-Host "INFO: Verifying ISO at $($config.IsoPath)..." -ForegroundColor Cyan
if (-not (Test-Path -Path $config.IsoPath)) {
    Write-Host "ERROR: ISO not found." -ForegroundColor Red
    exit 1
}
Write-Host "INFO: ISO found." -ForegroundColor Green

# 1.4) SHA256 hash (informational)
Write-Host "INFO: Computing SHA256 hash..." -ForegroundColor Cyan
$actualHash = (Get-FileHash -Path $config.IsoPath -Algorithm SHA256).Hash
Write-Host "INFO: SHA256: $actualHash" -ForegroundColor Green

# ============================================================
# PHASE 2: Hardware / Firmware Requirement Checks
# ============================================================
Write-Host "`n=== PHASE 2: Hardware / Firmware Checks ===" -ForegroundColor Cyan

$hwIssues   = @()
$hwBlocking = $false

# 2.1) Disk Partition Style
Write-Host "INFO: [1/6] Checking disk partition style..." -ForegroundColor Cyan
try {
    $osDriveLetter = $env:SystemDrive -replace ':', ''
    $osDisk = $null
    if (Get-Command Get-Partition -ErrorAction SilentlyContinue) {
        $osPart = Get-Partition -DriveLetter $osDriveLetter -ErrorAction SilentlyContinue
        if ($osPart) {
            $osDisk = Get-Disk -Number $osPart.DiskNumber -ErrorAction SilentlyContinue
        }
    }
    if ($osDisk) {
        $partStyle = $osDisk.PartitionStyle
        Write-Host "INFO: Disk $($osDisk.Number) partition style: $partStyle" -ForegroundColor Gray
        if ($partStyle -eq 'GPT') {
            Write-Host "PASS: Disk is GPT." -ForegroundColor Green
        }
        elseif ($partStyle -eq 'MBR') {
            Write-Host "FAIL: Disk is MBR -- Windows 11 requires GPT!" -ForegroundColor Red
            $hwIssues  += "MBR disk (needs GPT conversion via mbr2gpt)"
            $hwBlocking = $true
        }
    }
    else {
        Write-Host "WARN: Could not determine disk partition style via Get-Disk." -ForegroundColor DarkYellow
    }
}
catch {
    Write-Host "WARN: Disk check error: $_" -ForegroundColor DarkYellow
}

# 2.2) UEFI vs Legacy
Write-Host "INFO: [2/6] Checking firmware type..." -ForegroundColor Cyan
try {
    $fwType = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" `
        -Name "PEFirmwareType" -ErrorAction Stop).PEFirmwareType
    if ($fwType -eq 2) {
        Write-Host "PASS: UEFI firmware." -ForegroundColor Green
    }
    else {
        Write-Host "FAIL: Legacy BIOS -- Windows 11 requires UEFI!" -ForegroundColor Red
        $hwIssues  += "Legacy BIOS (needs UEFI)"
        $hwBlocking = $true
    }
}
catch {
    Write-Host "WARN: Could not determine firmware type." -ForegroundColor DarkYellow
}

# 2.3) Secure Boot
Write-Host "INFO: [3/6] Checking Secure Boot..." -ForegroundColor Cyan
$secureBootOff = $false
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($secureBoot) {
        Write-Host "PASS: Secure Boot is ON." -ForegroundColor Green
    }
    else {
        Write-Host "WARN: Secure Boot is OFF." -ForegroundColor DarkYellow
        $hwIssues     += "Secure Boot disabled"
        $secureBootOff = $true
    }
}
catch [System.PlatformNotSupportedException] {
    Write-Host "WARN: Secure Boot not supported (Legacy BIOS?)." -ForegroundColor DarkYellow
    $hwIssues     += "Secure Boot not supported"
    $secureBootOff = $true
}
catch {
    Write-Host "WARN: Could not determine Secure Boot status." -ForegroundColor DarkYellow
}

# 2.4) TPM
Write-Host "INFO: [4/6] Checking TPM..." -ForegroundColor Cyan
$tpmOk = $false
try {
    $tpm = Get-WmiObject -Namespace "root\cimv2\Security\MicrosoftTpm" `
        -Class Win32_Tpm -ErrorAction Stop
    if ($tpm) {
        $tpmVersion = ($tpm.SpecVersion -split ',')[0].Trim()
        Write-Host "INFO: TPM version: $tpmVersion" -ForegroundColor Gray
        $majorVer = 0.0
        try { $majorVer = [decimal]$tpmVersion } catch {}
        if ($majorVer -ge 2.0) {
            Write-Host "PASS: TPM 2.0 detected." -ForegroundColor Green
            $tpmOk = $true
        }
        else {
            Write-Host "WARN: TPM $tpmVersion -- Windows 11 requires 2.0." -ForegroundColor DarkYellow
            $hwIssues += "TPM version $tpmVersion (needs 2.0)"
        }
    }
    else {
        Write-Host "WARN: No TPM detected." -ForegroundColor DarkYellow
        $hwIssues += "No TPM detected"
    }
}
catch {
    Write-Host "WARN: TPM query failed." -ForegroundColor DarkYellow
    $hwIssues += "TPM query failed"
}

# 2.5) CPU
Write-Host "INFO: [5/6] Checking CPU..." -ForegroundColor Cyan
$cpuUnsupported = $false
try {
    $cpu     = Get-WmiObject Win32_Processor | Select-Object -First 1
    $cpuName = $cpu.Name.Trim()
    Write-Host "INFO: CPU: $cpuName" -ForegroundColor Gray

    $cpuOk     = $true
    $cpuReason = ""

    if ($cpu.AddressWidth -ne 64) {
        $cpuOk     = $false
        $cpuReason = "Not a 64-bit processor"
    }
    if ($cpu.NumberOfCores -lt 2) {
        $cpuOk     = $false
        $cpuReason = "Fewer than 2 cores"
    }

    # Intel generation heuristic
    if ($cpuName -match 'Intel.*Core.*i[3579]-(\d)') {
        $gen = [int]$Matches[1]
        if ($gen -lt 8) {
            $cpuOk          = $false
            $cpuReason      = "Intel Gen $gen -- Windows 11 requires 8th Gen+"
            $cpuUnsupported = $true
        }
    }

    # AMD Ryzen generation heuristic
    if ($cpuName -match 'AMD Ryzen \d \d(\d)\d\d') {
        $ryzenGen = [int]$Matches[1]
        if ($ryzenGen -lt 2) {
            $cpuOk          = $false
            $cpuReason      = "AMD Ryzen 1st Gen -- Windows 11 requires Ryzen 2000+"
            $cpuUnsupported = $true
        }
    }

    if ($cpuOk) {
        Write-Host "PASS: CPU meets requirements." -ForegroundColor Green
    }
    else {
        Write-Host "WARN: $cpuReason ($cpuName)" -ForegroundColor DarkYellow
        $hwIssues += "$cpuReason ($cpuName)"
    }
}
catch {
    Write-Host "WARN: CPU check failed: $_" -ForegroundColor DarkYellow
}

# 2.6) RAM
Write-Host "INFO: [6/6] Checking RAM..." -ForegroundColor Cyan
try {
    $totalRAM_GB = [math]::Round(
        (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1
    )
    Write-Host "INFO: RAM: $totalRAM_GB GB" -ForegroundColor Gray
    if ($totalRAM_GB -ge 4) {
        Write-Host "PASS: RAM >= 4 GB." -ForegroundColor Green
    }
    else {
        Write-Host "FAIL: RAM $totalRAM_GB GB -- need 4 GB minimum!" -ForegroundColor Red
        $hwIssues  += "RAM $totalRAM_GB GB (minimum 4 GB)"
        $hwBlocking = $true
    }
}
catch {
    Write-Host "WARN: RAM check failed." -ForegroundColor DarkYellow
}

# --- Hardware check summary ---
if ($hwBlocking) {
    $issueList = $hwIssues -join '; '
    Write-Host "`nFATAL: Hard hardware blockers found that cannot be bypassed: $issueList" -ForegroundColor Red
    exit 1
}

# ============================================================
# PHASE 3: Appraiser Blocker Scan (from previous upgrade attempts)
# ============================================================
Write-Host "`n=== PHASE 3: Appraiser Blocker Scan ===" -ForegroundColor Cyan

$appraiserPaths = @(
    "$env:SystemDrive\`$WINDOWS.~BT",
    "$env:SystemDrive\Windows\Panther"
)

$appraiserFiles = @()
foreach ($basePath in $appraiserPaths) {
    if (Test-Path $basePath) {
        $found = Get-ChildItem -Path $basePath -Filter "*_APPRAISER_HumanReadable.xml" `
                 -Recurse -ErrorAction SilentlyContinue -Force
        if ($found) { $appraiserFiles += $found }
    }
}

$appraiserBlockers = @()

if ($appraiserFiles.Count -gt 0) {
    Write-Host "INFO: Found $($appraiserFiles.Count) appraiser file(s)." -ForegroundColor Gray

    foreach ($file in $appraiserFiles) {
        Write-Host "INFO: Parsing $($file.FullName)..." -ForegroundColor Gray
        $lines = Get-Content -Path $file.FullName -Force -ErrorAction SilentlyContinue
        if (-not $lines) { continue }

        $totalLines     = $lines.Count
        $inAssetBlock   = $false
        $assetStartLine = 0
        $assetLines     = @()

        for ($i = 0; $i -lt $totalLines; $i++) {
            $line = $lines[$i]

            if ($line -match '<Asset[\s>]') {
                $inAssetBlock   = $true
                $assetStartLine = $i
                $assetLines     = @($line)

                if ($line -match '/>' -or $line -match '</Asset>') {
                    $inAssetBlock = $false
                }
                else { continue }
            }
            elseif ($inAssetBlock) {
                $assetLines += $line
                if ($line -match '</Asset>') {
                    $inAssetBlock = $false
                }
                else { continue }
            }
            else { continue }

            # Analyze closed <Asset> block
            $assetText = $assetLines -join "`n"

            if ($assetText -notmatch 'DT_ANY_FMC_BlockingApplication') { continue }

            $isBlocking = $false
            if ($assetText -match 'DT_ANY_FMC_BlockingApplication[^>]*Value\s*=\s*"True"') {
                $isBlocking = $true
            }
            elseif ($assetText -match 'DT_ANY_FMC_BlockingApplication' -and $assetText -match '>True<') {
                $isBlocking = $true
            }

            if (-not $isBlocking) { continue }

            $blockLineNum = $assetStartLine + 1
            $blockEndNum  = $i + 1

            # Extract LowerCaseLongPathUnexpanded
            $pathValue   = $null
            $pathLineNum = $null
            for ($j = 0; $j -lt $assetLines.Count; $j++) {
                if ($assetLines[$j] -match 'LowerCaseLongPathUnexpanded') {
                    $pathLineNum = $assetStartLine + $j + 1
                    if ($assetLines[$j] -match 'Value\s*=\s*"([^"]+)"') {
                        $pathValue = $Matches[1]
                    }
                    elseif ($assetLines[$j] -match '>([^<]+)<') {
                        $pathValue = $Matches[1]
                    }
                    break
                }
            }

            # Extract SdbAppName as fallback
            $sdbValue   = $null
            $sdbLineNum = $null
            for ($j = 0; $j -lt $assetLines.Count; $j++) {
                if ($assetLines[$j] -match 'SdbAppName') {
                    $sdbLineNum = $assetStartLine + $j + 1
                    if ($assetLines[$j] -match 'Value\s*=\s*"([^"]+)"') {
                        $sdbValue = $Matches[1]
                    }
                    elseif ($assetLines[$j] -match '>([^<]+)<') {
                        $sdbValue = $Matches[1]
                    }
                    break
                }
            }

            if ($pathValue) {
                Write-Host "BLOCKER: LowerCaseLongPathUnexpanded on line $pathLineNum : $pathValue" -ForegroundColor Red
                Write-Host "         <Asset> block: lines $blockLineNum-$blockEndNum" -ForegroundColor Gray
                for ($j = 0; $j -lt $assetLines.Count; $j++) {
                    $absLine = $assetStartLine + $j + 1
                    $isMatch = ($assetLines[$j] -match 'LowerCaseLongPathUnexpanded')
                    if ($isMatch) {
                        Write-Host "     >>> $($absLine): $($assetLines[$j].TrimEnd())" -ForegroundColor White
                    }
                    else {
                        Write-Host "         $($absLine): $($assetLines[$j].TrimEnd())" -ForegroundColor DarkGray
                    }
                }
                $appraiserBlockers += "File: $pathValue (line $pathLineNum)"
            }
            elseif ($sdbValue) {
                Write-Host "BLOCKER: SdbAppName on line $sdbLineNum : $sdbValue" -ForegroundColor Red
                Write-Host "         (No file path -- may indicate free space issue)" -ForegroundColor DarkYellow
                $appraiserBlockers += "SdbAppName: $sdbValue (line $sdbLineNum)"
            }
            else {
                Write-Host "BLOCKER: Unknown blocking <Asset> at lines $blockLineNum-$blockEndNum (no path or app name)" -ForegroundColor DarkYellow
                $appraiserBlockers += "Unknown blocker at lines $blockLineNum-$blockEndNum"
            }
        }
    }
}
else {
    Write-Host "INFO: No appraiser XML files found (clean slate or first attempt)." -ForegroundColor Gray
}

if ($appraiserBlockers.Count -gt 0) {
    $blockerSummary = $appraiserBlockers -join '; '
    Write-Host "`nFATAL: Appraiser blockers detected: $blockerSummary" -ForegroundColor Red
    Write-Host "ACTION: Remove/uninstall the blocking application(s) listed above and re-run." -ForegroundColor Yellow
    exit 1
}
else {
    Write-Host "PASS: No appraiser blockers found." -ForegroundColor Green
}

# ============================================================
# PHASE 4: Apply Bypass (if unsupported hardware detected)
# ============================================================
$needsBypass = ($hwIssues.Count -gt 0)

if ($needsBypass) {
    $issueList = $hwIssues -join '; '
    Write-Host "`n=== PHASE 4: Applying Bypass for Unsupported Hardware ===" -ForegroundColor Cyan
    Write-Host "INFO: Issues detected: $issueList" -ForegroundColor DarkYellow
    Write-Host "INFO: Bypass mode: $($config.BypassMode)" -ForegroundColor Gray

    # Detect if already running Windows 11
    $currentBuild = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
        -Name CurrentBuildNumber).CurrentBuildNumber
    $productName  = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
        -Name ProductName).ProductName
    if ($currentBuild -ge 22000) {
        Write-Host "INFO: Currently running $productName (Build $currentBuild) on unsupported hardware." -ForegroundColor Gray
    }

    # 4.1) Apply MoSetup registry key
    if ($config.AutoApplyRegKey) {
        Write-Host "INFO: Applying MoSetup AllowUpgradesWithUnsupportedTPMOrCPU registry key..." -ForegroundColor Cyan
        try {
            $moSetupPath = "HKLM:\SYSTEM\Setup\MoSetup"
            if (-not (Test-Path $moSetupPath)) {
                New-Item -Path $moSetupPath -Force | Out-Null
            }
            Set-ItemProperty -Path $moSetupPath `
                -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -Value 1 -Type DWord -Force
            $verify = (Get-ItemProperty -Path $moSetupPath `
                -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -ErrorAction Stop
            ).AllowUpgradesWithUnsupportedTPMOrCPU
            if ($verify -eq 1) {
                Write-Host "PASS: MoSetup bypass key applied and verified." -ForegroundColor Green
            }
            else {
                Write-Host "WARN: MoSetup key written but verification returned: $verify" -ForegroundColor DarkYellow
            }
        }
        catch {
            Write-Host "ERROR: Failed to apply MoSetup registry key: $_" -ForegroundColor Red
        }
    }

    # 4.2) Build setup arguments based on bypass mode
    switch ($config.BypassMode) {

        'interactive' {
            Write-Host "INFO: Interactive mode -- setup wizard will appear. User must select 'Keep files, settings, and apps'." -ForegroundColor DarkYellow
            $setupArgs = @(
                '/product server',
                '/DynamicUpdate Disable',
                '/Compat IgnoreWarning',
                '/MigrateDrivers All',
                '/Eula Accept'
            )
        }

        'unattended' {
            Write-Host "INFO: Unattended mode -- using registry bypass + silent setup." -ForegroundColor Cyan

            if ($config.WriteSetupConfigIni) {
                $configDir = "$env:SystemDrive\Users\Default\AppData\Local\Microsoft\Windows\WSUS"
                if (-not (Test-Path $configDir)) {
                    New-Item -Path $configDir -ItemType Directory -Force | Out-Null
                }
                $configContent = @(
                    '[SetupConfig]',
                    'Priority=Normal',
                    'DynamicUpdate=Disable',
                    'Compat=IgnoreWarning',
                    'MigrateDrivers=All'
                ) -join "`r`n"
                $configFile = Join-Path $configDir 'setupconfig.ini'
                Set-Content -Path $configFile -Value $configContent -Force -Encoding ASCII
                Write-Host "PASS: setupconfig.ini written to $configFile" -ForegroundColor Green
            }

            $setupArgs = @(
                '/Auto Upgrade',
                '/Quiet',
                '/Eula Accept',
                '/DynamicUpdate Disable',
                '/Compat IgnoreWarning'
            )
        }

        default {
            Write-Host "ERROR: Unknown BypassMode '$($config.BypassMode)'. Use 'interactive' or 'unattended'." -ForegroundColor Red
            exit 1
        }
    }
}
else {
    Write-Host "`n=== PHASE 4: No Bypass Needed ===" -ForegroundColor Cyan
    Write-Host "PASS: All hardware checks passed. Using standard upgrade." -ForegroundColor Green
    $setupArgs = $config.StandardArgs
}

Write-Host "INFO: Setup arguments: $($setupArgs -join ' ')" -ForegroundColor Gray

# ============================================================
# PHASE 5: Mount ISO & Launch Setup
# ============================================================
Write-Host "`n=== PHASE 5: Mount ISO & Launch Setup ===" -ForegroundColor Cyan

Write-Host "INFO: Mounting ISO..." -ForegroundColor Cyan
try {
    $disk  = Mount-DiskImage -ImagePath $config.IsoPath -PassThru -ErrorAction Stop
    $vol   = Get-Volume -DiskImage $disk
    $drive = "$($vol.DriveLetter):"
    Write-Host "INFO: Mounted at $drive" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to mount ISO: $_" -ForegroundColor Red
    exit 1
}

# Verify setup.exe exists
$setupExe = "$drive\setup.exe"
if (-not (Test-Path $setupExe)) {
    Write-Host "ERROR: setup.exe not found at $setupExe" -ForegroundColor Red
    Dismount-DiskImage -ImagePath $config.IsoPath -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "INFO: Starting Windows Setup..." -ForegroundColor Cyan
try {
    Start-Process -FilePath $setupExe -ArgumentList $setupArgs -Verb RunAs -PassThru | Out-Null
    Write-Host "INFO: Setup launched successfully from $drive" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to launch setup: $_" -ForegroundColor Red
    Dismount-DiskImage -ImagePath $config.IsoPath -ErrorAction SilentlyContinue
    exit 1
}

# ============================================================
# PHASE 6: Monitor Setup Processes
# ============================================================
Write-Host "`n=== PHASE 6: Monitoring Setup ($($config.MonitorSeconds) seconds) ===" -ForegroundColor Cyan

$timer          = [Diagnostics.Stopwatch]::StartNew()
$noProcessCount = 0

while ($timer.Elapsed.TotalSeconds -lt $config.MonitorSeconds) {
    Start-Sleep 5
    $list = Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath.StartsWith($drive)
    }
    if (-not $list) {
        $noProcessCount++
        # Allow a few misses before declaring failure
        if ($noProcessCount -ge 6) {
            $elapsed = [math]::Round($timer.Elapsed.TotalSeconds, 0)
            Write-Host "WARN: No setup processes detected under $drive for 30+ seconds (at ${elapsed}s). Upgrade may have failed." -ForegroundColor Red

            # Check setupact.log for error hints
            $pantherLog = "$env:SystemDrive\`$WINDOWS.~BT\Sources\Panther\setupact.log"
            if (Test-Path $pantherLog) {
                $lastErrors = Get-Content $pantherLog -Tail 20 -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match 'Error' }
                if ($lastErrors) {
                    Write-Host "INFO: Recent errors from setupact.log:" -ForegroundColor DarkYellow
                    $lastErrors | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
                }
            }

            # If unattended failed, suggest switching to interactive
            if ($needsBypass -and $config.BypassMode -eq 'unattended') {
                Write-Host "" -ForegroundColor Yellow
                Write-Host "TIP: Unattended bypass may have failed. Try changing config:" -ForegroundColor Yellow
                Write-Host "     BypassMode = 'interactive'" -ForegroundColor Yellow
                Write-Host "     This will use /product server and show the setup wizard." -ForegroundColor Yellow
            }
            return
        }
    }
    else {
        $noProcessCount = 0
    }
}

Write-Host "INFO: Upgrade appears to be in progress." -ForegroundColor Green
