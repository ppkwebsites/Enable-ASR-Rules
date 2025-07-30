# Enable-ASRRules.ps1
# Script to enable 7 specific ASR rules in Block mode
# Requires administrative privileges
# Compatible with Windows PowerShell 5.1

# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires administrative privileges. Please run PowerShell as Administrator." -ForegroundColor Red
    exit
}

# Start logging
Start-Transcript -Path "C:\Users\ppk\Desktop\ASR-Log.txt" -Force

# List of 7 ASR rule GUIDs and their descriptions
$asrRuleIds = @{
    "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers"
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from lsass.exe"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
    "33DDEDF1-C6E0-47CB-833E-DE6133960387" = "Block rebooting machine in Safe Mode"
    "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB" = "Block use of copied or impersonated system tools"
}

# Check for pending reboot
if ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") -or
    (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -or
    (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)) {
    Write-Host "A system reboot is pending. Please restart your PC before enabling ASR rules." -ForegroundColor Red
    Write-Host "Exiting script until reboot is completed." -ForegroundColor Red
    Stop-Transcript
    exit
}

# Check if Microsoft Defender is enabled
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    if (-not $defenderStatus.AntivirusEnabled) {
        Write-Host "Microsoft Defender Antivirus is not enabled. ASR rules cannot be applied." -ForegroundColor Red
        Write-Host "Please ensure no third-party antivirus is active and enable Defender in Windows Security." -ForegroundColor Yellow
        Stop-Transcript
        exit
    }
    if (-not $defenderStatus.RealTimeProtectionEnabled) {
        Write-Host "Microsoft Defender Real-time Protection is disabled. Enabling it now..." -ForegroundColor Yellow
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Write-Host "Real-time Protection enabled." -ForegroundColor Green
        }
        catch {
            Write-Host "Error enabling Real-time Protection: $($_.Exception.Message)" -ForegroundColor Red
            Stop-Transcript
            exit
        }
    }
    Write-Host "Microsoft Defender is active (AntivirusEnabled: $($defenderStatus.AntivirusEnabled), RealTimeProtectionEnabled: $($defenderStatus.RealTimeProtectionEnabled))." -ForegroundColor Green
}
catch {
    Write-Host "Error checking Defender status: $($_.Exception.Message)" -ForegroundColor Red
    Stop-Transcript
    exit
}

# Clear existing ASR rules to avoid conflicts
try {
    Write-Host "Clearing existing ASR rules..." -ForegroundColor Cyan
    Set-MpPreference -AttackSurfaceReductionRules_Ids $null -AttackSurfaceReductionRules_Actions $null -ErrorAction Stop
    Write-Host "Existing ASR rules cleared." -ForegroundColor Green
}
catch {
    Write-Host "Error clearing ASR rules: $($_.Exception.Message)" -ForegroundColor Red
}

# Enable each ASR rule
Write-Host "`nEnabling ASR rules..." -ForegroundColor Cyan
$failedRules = @()
foreach ($id in $asrRuleIds.Keys) {
    $ruleName = $asrRuleIds[$id]
    try {
        Write-Host "Enabling $ruleName ($id)..." -ForegroundColor Cyan
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
        Start-Sleep -Seconds 1
        # Verify immediately
        $currentRules = Get-MpPreference -ErrorAction Stop | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
        $currentActions = Get-MpPreference -ErrorAction Stop | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
        $index = [array]::IndexOf($currentRules, $id)
        if ($index -ge 0 -and $currentActions[$index] -eq 1) {
            Write-Host "Successfully enabled: $ruleName ($id) - Block mode" -ForegroundColor Green
        }
        else {
            Write-Host "Failed to verify: $ruleName ($id) not active" -ForegroundColor Yellow
            $failedRules += "$ruleName ($id)"
        }
    }
    catch {
        Write-Host "Error enabling $ruleName ($id): $($_.Exception.Message)" -ForegroundColor Red
        $failedRules += "$ruleName ($id)"
    }
}

# Final verification
Write-Host "`nFinal verification of applied ASR rules..." -ForegroundColor Cyan
try {
    $currentRules = Get-MpPreference -ErrorAction Stop | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
    $currentActions = Get-MpPreference -ErrorAction Stop | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
    foreach ($id in $asrRuleIds.Keys) {
        $ruleName = $asrRuleIds[$id]
        $index = [array]::IndexOf($currentRules, $id)
        if ($index -ge 0 -and $currentActions[$index] -eq 1) {
            Write-Host "Rule active: $ruleName ($id) - Block mode" -ForegroundColor Green
        }
        else {
            Write-Host "Rule not active: $ruleName ($id)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Host "Error verifying ASR rules: $($_.Exception.Message)" -ForegroundColor Red
}

# Attempt to restart Windows Defender service
Write-Host "`nAttempting to restart Windows Defender service..." -ForegroundColor Cyan
try {
    Restart-Service -Name WinDefend -Force -ErrorAction Stop
    Write-Host "Windows Defender service restarted successfully." -ForegroundColor Green
}
catch {
    Write-Host "Error restarting WinDefend service: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "A reboot may be required to apply changes." -ForegroundColor Yellow
}

# Summary
Write-Host "`nASR rules configuration completed." -ForegroundColor Cyan
if ($failedRules.Count -gt 0) {
    Write-Host "Failed to enable the following rules:" -ForegroundColor Red
    $failedRules | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}
else {
    Write-Host "All specified ASR rules have been successfully enabled." -ForegroundColor Green
}
Write-Host "Please run check.ps1 to verify the updated ASR rule status." -ForegroundColor Yellow
Write-Host "Log saved to C:\Users\ppk\Desktop\ASR-Log.txt" -ForegroundColor Yellow

Stop-Transcript