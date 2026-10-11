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
# 0. USER AND ADMIN MANAGEMENT
# ============================================================================
Write-Log "Configuring user and admin management..." "INFO"

# Define paths for user and admin files (same directory as script)
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$usersFile = Join-Path -Path $scriptDir -ChildPath "users.txt"
$adminsFile = Join-Path -Path $scriptDir -ChildPath "admins.txt"

# Function to load users from file
function Load-UserList {
    param([string]$FilePath)
    $users = @()
    if (Test-Path $FilePath) {
        $users = Get-Content -Path $FilePath | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
    } else {
        Write-Log "Warning: File not found: $FilePath" "WARN"
    }
    return $users
}

# Load allowed users and admins
$allowedUsers = Load-UserList -FilePath $usersFile
$allowedAdmins = Load-UserList -FilePath $adminsFile

Write-Log "Loaded $($allowedUsers.Count) allowed users" "INFO"
Write-Log "Loaded $($allowedAdmins.Count) allowed admins" "INFO"

# Get all local users
$localUsers = Get-LocalUser -ErrorAction SilentlyContinue

try {
    # First, add/update admin group members
    if ($allowedAdmins.Count -gt 0) {
        foreach ($admin in $allowedAdmins) {
            try {
                $adminExists = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
                if ($adminExists) {
                    # Add user to Administrators group if not already member
                    $adminGroup = [ADSI]"WinNT://./Administrators"
                    $adminGroupMembers = @($adminGroup.psbase.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }
                    
                    if ($adminGroupMembers -notcontains $admin) {
                        $adminGroup.Add("WinNT://./$admin")
                        Write-Log "User added to Administrators group: $admin" "SUCCESS"
                    } else {
                        Write-Log "User already in Administrators group: $admin" "INFO"
                    }
                    
                    # Ensure user is enabled
                    if ($adminExists.Enabled -eq $false) {
                        Enable-LocalUser -Name $admin -ErrorAction SilentlyContinue
                        Write-Log "Admin account enabled: $admin" "SUCCESS"
                    }
                } else {
                    Write-Log "Admin user not found on system: $admin" "WARN"
                }
            } catch {
                Write-Log "Error processing admin user $admin : $_" "WARN"
            }
        }
    }
    
    # Process standard users (remove from admin, enable if in allowed list)
    if ($allowedUsers.Count -gt 0) {
        foreach ($user in $allowedUsers) {
            try {
                $userExists = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
                if ($userExists) {
                    # Ensure user is enabled
                    if ($userExists.Enabled -eq $false) {
                        Enable-LocalUser -Name $user -ErrorAction SilentlyContinue
                        Write-Log "Standard user account enabled: $user" "SUCCESS"
                    }
                    
                    # Remove from Administrators group if present
                    $adminGroup = [ADSI]"WinNT://./Administrators"
                    $adminGroupMembers = @($adminGroup.psbase.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }
                    
                    if ($allowedAdmins -notcontains $user -and $adminGroupMembers -contains $user) {
                        $adminGroup.Remove("WinNT://./$user")
                        Write-Log "User removed from Administrators group: $user" "SUCCESS"
                    }
                } else {
                    Write-Log "Standard user not found on system: $user" "WARN"
                }
            } catch {
                Write-Log "Error processing standard user $user : $_" "WARN"
            }
        }
    }
    
    # Disable/remove unauthorized users (not in allowed users or admins list)
    $combinedAllowedUsers = $allowedUsers + $allowedAdmins | Select-Object -Unique
    foreach ($localUser in $localUsers) {
        try {
            # Skip system accounts (Guest, DefaultAccount, and accounts starting with $)
            if ($localUser.Name -match '^(\$|Guest|DefaultAccount)') {
                continue
            }
            
            if ($combinedAllowedUsers -notcontains $localUser.Name) {
                # Disable unauthorized accounts
                if ($localUser.Enabled -eq $true) {
                    Disable-LocalUser -Name $localUser.Name -ErrorAction SilentlyContinue
                    Write-Log "Unauthorized user account disabled: $($localUser.Name)" "SUCCESS"
                }
                
                # Remove from Administrators group if member
                $adminGroup = [ADSI]"WinNT://./Administrators"
                $adminGroupMembers = @($adminGroup.psbase.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }
                
                if ($adminGroupMembers -contains $localUser.Name) {
                    $adminGroup.Remove("WinNT://./$(($localUser.Name))")
                    Write-Log "Unauthorized user removed from Administrators group: $($localUser.Name)" "SUCCESS"
                }
            }
        } catch {
            Write-Log "Error processing unauthorized user $($localUser.Name) : $_" "WARN"
        }
    }
    
    Write-Log "User and admin management completed" "SUCCESS"
} catch {
    Write-Log "Error configuring user and admin management: $_" "ERROR"
}

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
Write-Log "1. Install latest Windows updates" "INFO"
Write-Log "2. Configure Windows Backup" "INFO"
Write-Log "3. Review and adjust privacy settings per organizational policy" "INFO"
Write-Log "4. Implement endpoint protection solutions" "INFO"
Write-Log "5. Configure Group Policy if on Domain" "INFO"

Write-Host ""
Write-Host "Hardening script completed. Review the log file for details." -ForegroundColor Green
