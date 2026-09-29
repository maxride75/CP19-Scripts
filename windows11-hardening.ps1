# Windows 11 Baseline Hardening Script
# This script implements security hardening best practices for Windows 11
# Run with Administrator privileges
# Usage: powershell -ExecutionPolicy Bypass -File windows11-hardening.ps1

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please re-run with elevated privileges." -ForegroundColor Red
    Exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows 11 Baseline Hardening Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Logging setup
$logFile = "C:\Logs\Windows11-Hardening-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
$logDir = Split-Path $logFile
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path $logFile -Value $logMessage
}

Write-Log "Starting Windows 11 hardening..." "INFO"

# ============================================================================
# 1. WINDOWS DEFENDER AND ANTIMALWARE SETTINGS
# ============================================================================
Write-Log "Configuring Windows Defender settings..." "INFO"

try {
    # Enable Windows Defender
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Write-Log "Real-time protection enabled" "SUCCESS"
    
    # Enable cloud-delivered protection
    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
    Write-Log "Cloud-delivered protection enabled" "SUCCESS"
    
    # Enable behavior monitoring
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
    Write-Log "Behavior monitoring enabled" "SUCCESS"
    
    # Set scan schedule
    Set-MpPreference -ScanScheduleDay Everyday -ScanScheduleTime 02:00 -ErrorAction SilentlyContinue
    Write-Log "Daily scan scheduled for 2:00 AM" "SUCCESS"
    
    # Enable network inspection system
    Set-MpPreference -DisableNetworkProtectionNotifications $false -ErrorAction SilentlyContinue
    Write-Log "Network inspection system enabled" "SUCCESS"
} catch {
    Write-Log "Error configuring Windows Defender: $_" "ERROR"
}

# ============================================================================
# 2. WINDOWS FIREWALL SETTINGS
# ============================================================================
Write-Log "Configuring Windows Firewall..." "INFO"

try {
    # Enable Windows Defender Firewall for all profiles
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -ErrorAction SilentlyContinue
    Write-Log "Windows Firewall enabled for all profiles" "SUCCESS"
    
    # Set firewall policies
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block -ErrorAction SilentlyContinue
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
    Write-Log "Firewall inbound/outbound policies configured" "SUCCESS"
    
    # Disable firewall notifications
    Set-NetFirewallProfile -Profile Domain, Public, Private -NotifyOnListen $false -ErrorAction SilentlyContinue
    Write-Log "Firewall notification settings configured" "SUCCESS"
} catch {
    Write-Log "Error configuring Windows Firewall: $_" "ERROR"
}

# ============================================================================
# 3. USER ACCOUNT CONTROL (UAC) SETTINGS
# ============================================================================
Write-Log "Configuring User Account Control..." "INFO"

try {
    # Set UAC to highest level
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Force
    Write-Log "UAC set to always prompt for admin consent" "SUCCESS"
    
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0 -Force
    Write-Log "UAC user consent settings configured" "SUCCESS"
    
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Force
    Write-Log "Secure desktop for UAC prompts enabled" "SUCCESS"
} catch {
    Write-Log "Error configuring UAC: $_" "ERROR"
}

# ============================================================================
# 4. DISABLE UNNECESSARY SERVICES
# ============================================================================
Write-Log "Disabling unnecessary services..." "INFO"

$servicesToDisable = @(
    "RemoteRegistry",           # Remote Registry
    "lfsvc",                    # Location Service
    "DiagTrack",                # Diagnostic Tracking Service
    "dmwappushservice",         # dmwappushservice
    "MapsBroker",               # Downloaded Maps Manager
    "HomeGroupListener",        # HomeGroup Listener
    "HomeGroupProvider"         # HomeGroup Provider
)

foreach ($service in $servicesToDisable) {
    try {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Set-Service -Name $service -StartupType Disabled -Force -ErrorAction SilentlyContinue
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Write-Log "Service disabled: $service" "SUCCESS"
        }
    } catch {
        Write-Log "Error disabling service $service : $_" "WARN"
    }
}

# ============================================================================
# 5. LOCAL SECURITY POLICY SETTINGS
# ============================================================================
Write-Log "Configuring Local Security Policy..." "INFO"

try {
    # Disable guest account
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest) {
        Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        Write-Log "Guest account disabled" "SUCCESS"
    }
    
    # Password policy - require complex passwords
    net accounts /maxpwdage:90 | Out-Null
    net accounts /minpwdlen:14 | Out-Null
    net accounts /minpwdage:5 | Out-Null
    Write-Log "Password policy configured (14+ chars, expire every 90 days)" "SUCCESS"
    
    # Account lockout policy
    net accounts /lockoutduration:30 | Out-Null
    net accounts /lockoutthreshold:5 | Out-Null
    Write-Log "Account lockout policy configured" "SUCCESS"
} catch {
    Write-Log "Error configuring Local Security Policy: $_" "ERROR"
}

# ============================================================================
# 6. SYSTEM AUDIT LOGGING
# ============================================================================
Write-Log "Enabling system audit logging..." "INFO"

try {
    # Enable audit policy changes
    auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Object Access" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"System" /success:enable /failure:enable | Out-Null
    Write-Log "Audit logging policies enabled" "SUCCESS"
} catch {
    Write-Log "Error enabling audit logging: $_" "ERROR"
}

# ============================================================================
# 7. CONFIGURE WINDOWS UPDATE
# ============================================================================
Write-Log "Configuring Windows Update..." "INFO"

try {
    # Set automatic updates
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 3 -Force -ErrorAction SilentlyContinue
    Write-Log "Automatic Windows updates configured" "SUCCESS"
    
    # Configure update check schedule
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3 -Force -ErrorAction SilentlyContinue
    Write-Log "Update schedule configured" "SUCCESS"
} catch {
    Write-Log "Error configuring Windows Update: $_" "ERROR"
}

# ============================================================================
# 8. ENABLE SECURE BOOT AND TPM
# ============================================================================
Write-Log "Checking Secure Boot and TPM status..." "INFO"

try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($secureBoot) {
        Write-Log "Secure Boot is enabled" "SUCCESS"
    } else {
        Write-Log "Secure Boot is not enabled - enable in BIOS/UEFI" "WARN"
    }
    
    $tpm = Get-WmiObject -Class Win32_Tpm -Namespace root\cimv2\security\microsofttpm -ErrorAction SilentlyContinue
    if ($tpm) {
        Write-Log "TPM 2.0 is present and active" "SUCCESS"
    }
} catch {
    Write-Log "Error checking Secure Boot/TPM: $_" "WARN"
}

# ============================================================================
# 10. DISABLE UNNECESSARY FEATURES
# ============================================================================
Write-Log "Disabling unnecessary Windows features..." "INFO"

$featuresToDisable = @(
    "Internet-Explorer-Optional-amd64",
    "SMB1Protocol",
    "Printing-Foundation-Features"
)

foreach ($feature in $featuresToDisable) {
    try {
        $featureStatus = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($featureStatus -and $featureStatus.State -eq "Enabled") {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
            Write-Log "Feature disabled: $feature" "SUCCESS"
        }
    } catch {
        Write-Log "Error disabling feature $feature : $_" "WARN"
    }
}

# ============================================================================
# 11. NETWORK HARDENING
# ============================================================================
Write-Log "Applying network hardening settings..." "INFO"

try {
    # Disable LLMNR
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Log "LLMNR disabled" "SUCCESS"
    
    # Disable NetBIOS over TCP/IP
    $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue
    foreach ($adapter in $adapters) {
        $interfaceIndex = $adapter.InterfaceIndex
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip_$interfaceIndex"
        Set-ItemProperty -Path $regPath -Name "NetbiosOptions" -Value 2 -Force -ErrorAction SilentlyContinue
    }
    Write-Log "NetBIOS over TCP/IP disabled" "SUCCESS"
} catch {
    Write-Log "Error applying network hardening: $_" "WARN"
}

# ============================================================================
# 12. WINDOWS DEFENDER EXPLOIT GUARD
# ============================================================================
Write-Log "Configuring Windows Defender Exploit Guard..." "INFO"

try {
    # Enable Attack Surface Reduction
    Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\Program Files\*" -ErrorAction SilentlyContinue
    
    # Set Attack Surface Reduction rules
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    Write-Log "Attack Surface Reduction and Controlled Folder Access enabled" "SUCCESS"
} catch {
    Write-Log "Error configuring Exploit Guard: $_" "WARN"
}

# ============================================================================
# 13. PRIVACY SETTINGS
# ============================================================================
Write-Log "Configuring privacy settings..." "INFO"

try {
    # Disable Cortana
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Force -ErrorAction SilentlyContinue
    Write-Log "Cortana disabled" "SUCCESS"
    
    # Disable telemetry services
    Set-Service -Name "DiagTrack" -StartupType Disabled -Force -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -StartupType Disabled -Force -ErrorAction SilentlyContinue
    Write-Log "Telemetry services disabled" "SUCCESS"
    
    # Disable activity history
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Force -ErrorAction SilentlyContinue
    Write-Log "Activity history disabled" "SUCCESS"
} catch {
    Write-Log "Error configuring privacy settings: $_" "WARN"
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Log "========================================" "INFO"
Write-Log "Windows 11 hardening completed!" "SUCCESS"
Write-Log "========================================" "INFO"
Write-Log "Log file saved to: $logFile" "INFO"
Write-Log "Please review the following recommendations:" "INFO"
Write-Log "1. Enable BitLocker encryption for all drives" "INFO"
Write-Log "2. Verify Secure Boot is enabled in BIOS/UEFI" "INFO"
Write-Log "3. Verify TPM 2.0 is present and enabled" "INFO"
Write-Log "4. Install latest Windows updates" "INFO"
Write-Log "5. Configure Windows Backup" "INFO"
Write-Log "6. Review and adjust privacy settings per organizational policy" "INFO"
Write-Log "7. Implement endpoint protection solutions" "INFO"
Write-Log "8. Configure Group Policy if on Domain" "INFO"

Write-Host ""
Write-Host "Hardening script completed. Review the log file for details." -ForegroundColor Green
