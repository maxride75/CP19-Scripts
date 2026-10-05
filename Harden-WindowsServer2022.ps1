<#
.SYNOPSIS
    Windows Server 2022 Baseline Hardening Script with User and Admin Management
    
.DESCRIPTION
    This script implements comprehensive security hardening for Windows Server 2022,
    including user account management, administrative access control, and security
    policy enforcement. User and admin lists are read from configuration files in
    the executing user's home directory.
    
.PARAMETER UserConfigPath
    Path to user.txt configuration file (default: $env:USERPROFILE\user.txt)
    
.PARAMETER AdminConfigPath
    Path to admin.txt configuration file (default: $env:USERPROFILE\admin.txt)
    
.EXAMPLE
    .\Harden-WindowsServer2022.ps1 -Verbose
    
.NOTES
    Requires: Windows Server 2022, Administrator privileges
    Author: Security Team
    Version: 1.0
#>

[CmdletBinding()]
param(
    [string]$UserConfigPath = "$env:USERPROFILE\user.txt",
    [string]$AdminConfigPath = "$env:USERPROFILE\admin.txt"
)

# Requires Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# ============================================================================
# INITIALIZATION
# ============================================================================

Write-Verbose "=========================================="
Write-Verbose "Windows Server 2022 Hardening Script"
Write-Verbose "=========================================="
Write-Verbose "Execution started at: $(Get-Date)"

$ScriptVersion = "1.0"
$HardeningLog = "$env:USERPROFILE\Harden-WS2022_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $HardeningLog -Value $logMessage -ErrorAction SilentlyContinue
    Write-Verbose $Message
}

Write-Log "Script version: $ScriptVersion"
Write-Log "Configuration files: User=$UserConfigPath, Admin=$AdminConfigPath"

# ============================================================================
# CONFIGURATION FILE PARSING
# ============================================================================

function Read-ConfigFile {
    param(
        [string]$FilePath,
        [string]$ConfigType = "User"
    )
    
    Write-Log "Reading $ConfigType configuration from: $FilePath"
    
    if (-not (Test-Path $FilePath)) {
        Write-Log "Configuration file not found: $FilePath" "WARNING"
        return @()
    }
    
    try {
        $entries = @()
        $content = Get-Content -Path $FilePath -ErrorAction Stop
        
        foreach ($line in $content) {
            $line = $line.Trim()
            
            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) {
                continue
            }
            
            $entries += $line
        }
        
        Write-Log "Successfully read $($entries.Count) entries from $ConfigType configuration"
        return $entries
    }
    catch {
        Write-Log "Error reading $ConfigType configuration: $_" "ERROR"
        return @()
    }
}

$UserList = Read-ConfigFile -FilePath $UserConfigPath -ConfigType "User"
$AdminList = Read-ConfigFile -FilePath $AdminConfigPath -ConfigType "Admin"

# ============================================================================
# USER AND ADMIN MANAGEMENT
# ============================================================================

function Sync-UserAccounts {
    param([string[]]$Users)
    
    Write-Log "Synchronizing user accounts..."
    
    foreach ($username in $Users) {
        try {
            $existingUser = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
            
            if ($null -eq $existingUser) {
                Write-Log "Creating user account: $username"
                $null = New-LocalUser -Name $username -NoPassword -AccountNeverExpires
                Write-Log "User account created: $username" "INFO"
            }
            else {
                Write-Log "User account already exists: $username"
            }
        }
        catch {
            Write-Log "Error creating user account $username : $_" "ERROR"
        }
    }
}

function Sync-AdminAccounts {
    param([string[]]$Admins)
    
    Write-Log "Synchronizing administrative accounts..."
    
    foreach ($adminname in $Admins) {
        try {
            $existingUser = Get-LocalUser -Name $adminname -ErrorAction SilentlyContinue
            
            if ($null -eq $existingUser) {
                Write-Log "Creating admin account: $adminname"
                $null = New-LocalUser -Name $adminname -NoPassword -AccountNeverExpires
                Write-Log "Admin account created: $adminname"
            }
            
            # Add to Administrators group
            $adminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction Stop
            $groupMembers = Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            
            if ($groupMembers -notcontains "$env:COMPUTERNAME\$adminname") {
                Write-Log "Adding $adminname to Administrators group..."
                Add-LocalGroupMember -Group $adminGroup -Member $adminname -ErrorAction SilentlyContinue
                Write-Log "Successfully added $adminname to Administrators group"
            }
            else {
                Write-Log "$adminname is already a member of Administrators group"
            }
        }
        catch {
            Write-Log "Error managing admin account $adminname : $_" "ERROR"
        }
    }
}

# ============================================================================
# SECURITY POLICY HARDENING
# ============================================================================

function Set-PasswordPolicy {
    Write-Log "Configuring password policies..."
    
    try {
        $policies = @{
            "MaxPasswordAge"        = 90
            "MinPasswordAge"        = 1
            "MinPasswordLength"     = 14
            "PasswordHistorySize"   = 24
            "LockoutBadCount"       = 5
            "LockoutDuration"       = 30
            "LockoutObservationWindow" = 30
        }
        
        foreach ($key in $policies.Keys) {
            net accounts /$(Get-PolicyNetCommandParameter $key) $($policies[$key]) | Out-Null
            Write-Log "Set $key to $($policies[$key])"
        }
    }
    catch {
        Write-Log "Error setting password policies: $_" "ERROR"
    }
}

function Get-PolicyNetCommandParameter {
    param([string]$PolicyName)
    
    $map = @{
        "MaxPasswordAge"        = "maxpwage"
        "MinPasswordAge"        = "minpwage"
        "MinPasswordLength"     = "minpwlen"
        "PasswordHistorySize"   = "uniquepw"
        "LockoutBadCount"       = "lockoutthreshold"
        "LockoutDuration"       = "lockoutduration"
        "LockoutObservationWindow" = "lockoutwindow"
    }
    
    return $map[$PolicyName]
}

function Set-SecurityOptions {
    Write-Log "Configuring Windows security options..."
    
    try {
        # Disable unnecessary services
        $disableServices = @(
            "RemoteRegistry",
            "Telnet",
            "SNMP",
            "SimpleFileSharing"
        )
        
        foreach ($service in $disableServices) {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Disabled service: $service"
            }
        }
        
        # Enable security-related services
        $enableServices = @(
            "WinDefend",
            "SecurityHealthService",
            "Audiosrv"
        )
        
        foreach ($service in $enableServices) {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                Set-Service -Name $service -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name $service -ErrorAction SilentlyContinue
                Write-Log "Enabled service: $service"
            }
        }
    }
    catch {
        Write-Log "Error setting security options: $_" "ERROR"
    }
}

function Set-WindowsDefender {
    Write-Log "Configuring Windows Defender..."
    
    try {
        # Ensure Windows Defender is enabled
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableOnAccessProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScanningOfNetworkFiles $false -ErrorAction SilentlyContinue
        
        # Set to high alert level
        Set-MpPreference -ScanScheduleQuickScanTime 02:00:00 -ErrorAction SilentlyContinue
        
        Write-Log "Windows Defender configured successfully"
    }
    catch {
        Write-Log "Error configuring Windows Defender: $_" "WARNING"
    }
}

function Set-FirewallPolicy {
    Write-Log "Configuring Windows Firewall..."
    
    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
        Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block
        Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Allow
        Set-NetFirewallProfile -Profile Domain, Public, Private -NotifyOnListen True
        
        Write-Log "Windows Firewall policies configured"
    }
    catch {
        Write-Log "Error configuring Firewall: $_" "ERROR"
    }
}

function Set-AuditPolicy {
    Write-Log "Configuring audit and logging policies..."
    
    try {
        $auditPolicies = @(
            "Account Logon",
            "Account Management",
            "Logon/Logoff",
            "Object Access",
            "Privilege Use",
            "Detailed Tracking",
            "Policy Change",
            "System"
        )
        
        foreach ($policy in $auditPolicies) {
            auditpol /set /category:"$policy" /success:enable /failure:enable | Out-Null
            Write-Log "Audit policy enabled: $policy"
        }
    }
    catch {
        Write-Log "Error setting audit policies: $_" "ERROR"
    }
}

function Set-RegistryHardening {
    Write-Log "Applying registry hardening..."
    
    try {
        $registryChanges = @{
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" = @{
                "DisableRestrictedAdmin" = 0
                "DisableRestrictedAdminOutboundCreds" = 0
            }
            "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" = @{
                "RequireSignOrSeal" = 1
                "SealSecureChannel" = 1
                "SignSecureChannel" = 1
                "RequireStrongKey" = 1
            }
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                "ConsentPromptBehaviorAdmin" = 2
                "ConsentPromptBehaviorUser" = 0
                "EnableUIADesktopToggle" = 0
                "PromptOnSecureDesktop" = 1
                "UseLogonCredProvider" = 1
            }
        }
        
        foreach ($path in $registryChanges.Keys) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            
            foreach ($property in $registryChanges[$path].Keys) {
                $value = $registryChanges[$path][$property]
                Set-ItemProperty -Path $path -Name $property -Value $value -Force
                Write-Log "Registry set: $path\$property = $value"
            }
        }
    }
    catch {
        Write-Log "Error applying registry hardening: $_" "ERROR"
    }
}

function Set-SMBHardening {
    Write-Log "Hardening SMB configuration..."
    
    try {
        # Disable SMB v1 if available
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
        
        # Configure SMB signing
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -Confirm:$false
        Set-SmbServerConfiguration -EnableSecuritySignature $true -Force -Confirm:$false
        
        Write-Log "SMB hardening applied"
    }
    catch {
        Write-Log "Error hardening SMB: $_" "WARNING"
    }
}

function Set-NTLMHardening {
    Write-Log "Hardening NTLM configuration..."
    
    try {
        $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        
        if (-not (Test-Path $ntlmPath)) {
            New-Item -Path $ntlmPath -Force | Out-Null
        }
        
        # Restrict NTLM usage
        Set-ItemProperty -Path $ntlmPath -Name "NtlmMinClientSec" -Value 537395248 -Force
        Set-ItemProperty -Path $ntlmPath -Name "NtlmMinServerSec" -Value 537395248 -Force
        
        Write-Log "NTLM hardening applied"
    }
    catch {
        Write-Log "Error hardening NTLM: $_" "WARNING"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

try {
    Write-Log "Starting hardening process..."
    
    # User and Admin Management
    if ($UserList.Count -gt 0) {
        Sync-UserAccounts -Users $UserList
    }
    
    if ($AdminList.Count -gt 0) {
        Sync-AdminAccounts -Admins $AdminList
    }
    
    # Security Configuration
    Set-PasswordPolicy
    Set-SecurityOptions
    Set-WindowsDefender
    Set-FirewallPolicy
    Set-AuditPolicy
    Set-RegistryHardening
    Set-SMBHardening
    Set-NTLMHardening
    
    Write-Log "Hardening process completed successfully"
    Write-Log "Log file saved to: $HardeningLog"
    
    Write-Host "`n=========================================="
    Write-Host "Windows Server 2022 Hardening Complete"
    Write-Host "=========================================="
    Write-Host "Log file: $HardeningLog"
    Write-Host "Users configured: $($UserList.Count)"
    Write-Host "Admins configured: $($AdminList.Count)"
    Write-Host ""
}
catch {
    Write-Log "Critical error during hardening: $_" "ERROR"
    Write-Host "Critical error occurred. Check log file: $HardeningLog"
    exit 1
}
