<#
.SYNOPSIS
    Windows Server 2022 Baseline Hardening Script with User and Admin Management

.DESCRIPTION
    This script implements comprehensive security hardening for Windows Server 2022,
    including user account management, administrative access control, and security
    policy enforcement. User and admin lists are read from configuration files in
    the executing user's home directory unless overridden with parameters.

.PARAMETER UserConfigPath
    Path to user.txt configuration file (default: $env:USERPROFILE\user.txt)

.PARAMETER AdminConfigPath
    Path to admin.txt configuration file (default: $env:USERPROFILE\admin.txt)

.EXAMPLE
    .\Server2022_Hardening.ps1 -Verbose

.NOTES
    Requires: Windows Server 2022, Administrator privileges
    Author: Security Team
    Version: 2.0
#>

[CmdletBinding()]
param(
    [string]$UserConfigPath = "$env:USERPROFILE\user.txt",
    [string]$AdminConfigPath = "$env:USERPROFILE\admin.txt"
)

# Requires Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows Server 2022 Baseline Hardening Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Before proceeding, review the approved user/admin lists, update approved software, and remove unauthorized accounts." -ForegroundColor Yellow
Write-Host "If not using the default paths, pass -UserConfigPath and -AdminConfigPath with the correct files." -ForegroundColor Purple
Write-Host ""

$ScriptVersion = "2.0"
$HardeningLog = "$env:USERPROFILE\Harden-WS2022_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path $HardeningLog -Value $logMessage -ErrorAction SilentlyContinue
}

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

function New-RandomPassword {
    param([int]$Length = 16)

    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()_-+=[]{};,.?".ToCharArray()
    $password = @()

    for ($i = 0; $i -lt $Length; $i++) {
        $index = Get-Random -Minimum 0 -Maximum $chars.Count
        $password += $chars[$index]
    }

    return -join $password
}

function Set-RandomPasswordForUser {
    param([string]$Username)

    $newPassword = New-RandomPassword -Length 16
    $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force

    try {
        $user = Get-LocalUser -Name $Username -ErrorAction Stop
        if ($user) {
            $null = Set-LocalUser -Name $Username -Password $securePassword -ErrorAction Stop
            Write-Log "Random password assigned to account: $Username" "SUCCESS"
            return $newPassword
        }
        return $null
    }
    catch {
        Write-Log "Failed to assign random password to $Username: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Sync-UserAccounts {
    param([string[]]$Users)

    Write-Log "Synchronizing user accounts..."

    foreach ($username in $Users) {
        try {
            $existingUser = Get-LocalUser -Name $username -ErrorAction SilentlyContinue

            if ($null -eq $existingUser) {
                Write-Log "Creating user account: $username"
                $null = New-LocalUser -Name $username -NoPassword -AccountNeverExpires
                Write-Log "User account created: $username" "SUCCESS"
            }
            else {
                Write-Log "User account already exists: $username"
            }

            $existingUser = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
            if ($existingUser -and $existingUser.PasswordRequired -eq $false) {
                $null = Set-RandomPasswordForUser -Username $username
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
                Write-Log "Admin account created: $adminname" "SUCCESS"
            }
            else {
                Write-Log "Admin account already exists: $adminname"
            }

            $adminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction Stop
            $groupMembers = Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

            if ($groupMembers -notcontains "$env:COMPUTERNAME\$adminname") {
                Write-Log "Adding $adminname to Administrators group..."
                Add-LocalGroupMember -Group $adminGroup -Member $adminname -ErrorAction SilentlyContinue
                Write-Log "Successfully added $adminname to Administrators group" "SUCCESS"
            }
            else {
                Write-Log "$adminname is already a member of Administrators group"
            }

            $existingUser = Get-LocalUser -Name $adminname -ErrorAction SilentlyContinue
            if ($existingUser -and $existingUser.PasswordRequired -eq $false) {
                $null = Set-RandomPasswordForUser -Username $adminname
            }
        }
        catch {
            Write-Log "Error managing admin account $adminname : $_" "ERROR"
        }
    }
}

function Remove-UnauthorizedAccounts {
    param(
        [string[]]$AllowedUsers,
        [string[]]$AllowedAdmins
    )

    $combinedAllowedUsers = @($AllowedUsers + $AllowedAdmins | Select-Object -Unique)
    $localUsers = Get-LocalUser -ErrorAction SilentlyContinue

    foreach ($localUser in $localUsers) {
        try {
            if ($localUser.Name -match '^(\$|Guest|DefaultAccount|WDAGUtilityAccount)') {
                continue
            }

            if ($combinedAllowedUsers -notcontains $localUser.Name) {
                if ($localUser.Enabled -eq $true) {
                    Disable-LocalUser -Name $localUser.Name -ErrorAction SilentlyContinue
                    Write-Log "Unauthorized user account disabled: $($localUser.Name)" "SUCCESS"
                }

                $adminGroup = [ADSI]"WinNT://./Administrators"
                $adminGroupMembers = @($adminGroup.psbase.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }

                if ($adminGroupMembers -contains $localUser.Name) {
                    $adminGroup.Remove("WinNT://./$($localUser.Name)")
                    Write-Log "Unauthorized user removed from Administrators group: $($localUser.Name)" "SUCCESS"
                }
            }
        }
        catch {
            Write-Log "Error processing unauthorized user $($localUser.Name): $_" "WARN"
        }
    }
}

function Set-PasswordPolicy {
    Write-Log "Configuring password policies..."

    try {
        $policies = @{
            "MaxPasswordAge"           = 90
            "MinPasswordAge"           = 1
            "MinPasswordLength"        = 14
            "PasswordHistorySize"      = 24
            "LockoutBadCount"          = 5
            "LockoutDuration"          = 30
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
        "MaxPasswordAge"           = "maxpwage"
        "MinPasswordAge"           = "minpwage"
        "MinPasswordLength"        = "minpwlen"
        "PasswordHistorySize"      = "uniquepw"
        "LockoutBadCount"          = "lockoutthreshold"
        "LockoutDuration"          = "lockoutduration"
        "LockoutObservationWindow" = "lockoutwindow"
    }

    return $map[$PolicyName]
}

function Set-SecurityOptions {
    Write-Log "Configuring Windows security options..."

    try {
        $disableServices = @(
            "RemoteRegistry",
            "Telnet",
            "SNMP",
            "SimpleFileSharing",
            "Fax",
            "PrintSpooler"
        )

        foreach ($service in $disableServices) {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Disabled service: $service" "SUCCESS"
            }
        }

        $enableServices = @(
            "WinDefend",
            "SecurityHealthService",
            "Audiosrv",
            "W32Time"
        )

        foreach ($service in $enableServices) {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                Set-Service -Name $service -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name $service -ErrorAction SilentlyContinue
                Write-Log "Enabled service: $service" "SUCCESS"
            }
        }
    }
    catch {
        Write-Log "Error setting security options: $_" "ERROR"
    }
}

function Defender-AntiMal {
    Write-Log "Configuring Windows Defender antimalware settings..."

    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableOnAccessProtection $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScanningOfNetworkFiles $false -ErrorAction SilentlyContinue
        Set-MpPreference -ScanScheduleQuickScanTime 02:00:00 -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Write-Log "Windows Defender configured successfully" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring Windows Defender: $_" "WARNING"
    }
}

function Firewall {
    Write-Log "Configuring Windows Firewall..."

    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain, Public, Private -NotifyOnListen $false -ErrorAction SilentlyContinue
        Write-Log "Windows Firewall policies configured" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring Firewall: $_" "ERROR"
    }
}

function UAC {
    Write-Log "Configuring User Account Control..."

    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Force
        Write-Log "UAC settings configured" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring UAC: $_" "ERROR"
    }
}

function LocalSec {
    Write-Log "Configuring local security policy..."

    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest) {
            Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
            Write-Log "Guest account disabled" "SUCCESS"
        }

        net accounts /uniquepwd:5 | Out-Null
        net accounts /minpwlen:14 | Out-Null
        net accounts /maxpwage:90 | Out-Null
        net accounts /minpwage:1 | Out-Null
        net accounts /lockoutduration:30 | Out-Null
        net accounts /lockoutthreshold:5 | Out-Null

        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLmHash" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null

        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionPipes" -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionShares" -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null

        if (Get-Command ntrights -ErrorAction SilentlyContinue) {
            & ntrights +r SeDenyNetworkLogonRight -u Everyone | Out-Null
            Write-Log "Everyone removed from the right to log on over the network" "SUCCESS"
        }
        else {
            Write-Log "ntrights not available — remove Everyone from network logon rights manually in Local Security Policy" "WARN"
        }

        Write-Log "Local security hardening completed" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring local security policy: $_" "ERROR"
    }
}

function Audit {
    Write-Log "Enabling system audit logging..."

    try {
        auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Object Access" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"System" /success:enable /failure:enable | Out-Null
        Write-Log "Audit logging policies enabled" "SUCCESS"
    }
    catch {
        Write-Log "Error enabling audit logging: $_" "ERROR"
    }
}

function Updatepol {
    Write-Log "Configuring Windows Update..."

    try {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 3 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3 -Force -ErrorAction SilentlyContinue
        Write-Log "Automatic Windows updates configured" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring Windows Update: $_" "ERROR"
    }
}

function FeatureDisable {
    Write-Log "Disabling unnecessary Windows features..."

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
        }
        catch {
            Write-Log "Error disabling feature $feature : $_" "WARN"
        }
    }
}

function NetHarden {
    Write-Log "Applying network hardening..."

    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Log "LLMNR disabled" "SUCCESS"

        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue
        foreach ($adapter in $adapters) {
            $interfaceIndex = $adapter.InterfaceIndex
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip_$interfaceIndex"
            New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $regPath -Name "NetbiosOptions" -Value 2 -Force -ErrorAction SilentlyContinue
        }
        Write-Log "NetBIOS over TCP/IP disabled" "SUCCESS"
    }
    catch {
        Write-Log "Error applying network hardening: $_" "WARN"
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
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -Confirm:$false
        Set-SmbServerConfiguration -EnableSecuritySignature $true -Force -Confirm:$false
        Write-Log "SMB hardening applied" "SUCCESS"
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

        Set-ItemProperty -Path $ntlmPath -Name "NtlmMinClientSec" -Value 537395248 -Force
        Set-ItemProperty -Path $ntlmPath -Name "NtlmMinServerSec" -Value 537395248 -Force
        Write-Log "NTLM hardening applied" "SUCCESS"
    }
    catch {
        Write-Log "Error hardening NTLM: $_" "WARNING"
    }
}

function Search-UnauthorizedFiles {
    Write-Log "Searching for unauthorized files in user and public directories..."

    $roots = @(
        "$env:SystemDrive\Users",
        "$env:SystemDrive\Users\Public"
    )

    $targetExtensions = @(
        '.mp3', '.wav', '.flac', '.m4a', '.aac', '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.iso'
    )

    $matches = @()

    foreach ($root in $roots) {
        if (Test-Path $root) {
            $files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if ($targetExtensions -contains $file.Extension.ToLowerInvariant()) {
                    $matches += $file.FullName
                }
            }
        }
    }

    if ($matches.Count -gt 0) {
        foreach ($match in $matches) {
            Write-Log "Unauthorized file found: $match" "WARN"
        }
    }
    else {
        Write-Log "No unauthorized music or archive files were found in user/public directories." "SUCCESS"
    }
}

function Summary {
    Write-Log "========================================" "INFO"
    Write-Log "Windows Server 2022 hardening completed!" "SUCCESS"
    Write-Log "========================================" "INFO"
    Write-Log "Log file saved to: $HardeningLog" "INFO"
    Write-Log "Please review the following recommendations:" "INFO"
    Write-Log "1. Install latest Windows updates" "INFO"
    Write-Log "2. Configure Windows Backup / System State backups" "INFO"
    Write-Log "3. Review and adjust security settings per organizational policy" "INFO"
    Write-Log "4. Implement endpoint protection and monitoring" "INFO"
    Write-Log "5. Confirm domain policy inheritance and server role restrictions" "INFO"

    Write-Host ""
    Write-Host "Hardening script completed. Review the log file for details." -ForegroundColor Green
}

function Run-AllModules {
    param(
        [string[]]$Users,
        [string[]]$Admins
    )

    Write-Log "Starting hardening process..."

    if ($Users.Count -gt 0) { Sync-UserAccounts -Users $Users }
    if ($Admins.Count -gt 0) { Sync-AdminAccounts -Admins $Admins }
    Remove-UnauthorizedAccounts -AllowedUsers $Users -AllowedAdmins $Admins

    Set-PasswordPolicy
    Set-SecurityOptions
    Defender-AntiMal
    Firewall
    UAC
    LocalSec
    Audit
    Updatepol
    FeatureDisable
    NetHarden
    Set-RegistryHardening
    Set-SMBHardening
    Set-NTLMHardening
    Search-UnauthorizedFiles

    Write-Log "Hardening process completed successfully" "SUCCESS"
    Write-Log "Log file saved to: $HardeningLog" "INFO"

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Windows Server 2022 Hardening Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Log file: $HardeningLog" -ForegroundColor Cyan
    Write-Host "Users configured: $($Users.Count)" -ForegroundColor Cyan
    Write-Host "Admins configured: $($Admins.Count)" -ForegroundColor Cyan
    Write-Host ""
}

function Show-ModuleMenu {
    $modules = @(
        @{ Name = "User and Admin Management"; Action = { param($u,$a) Sync-UserAccounts -Users $u; Sync-AdminAccounts -Admins $a; Remove-UnauthorizedAccounts -AllowedUsers $u -AllowedAdmins $a } },
        @{ Name = "Password and Local Security Policy"; Action = { Set-PasswordPolicy; LocalSec } },
        @{ Name = "Windows Defender"; Action = { Defender-AntiMal } },
        @{ Name = "Windows Firewall"; Action = { Firewall } },
        @{ Name = "Security Services"; Action = { Set-SecurityOptions } },
        @{ Name = "User Account Control"; Action = { UAC } },
        @{ Name = "System Audit Logging"; Action = { Audit } },
        @{ Name = "Windows Update Policy"; Action = { Updatepol } },
        @{ Name = "Registry Hardening"; Action = { Set-RegistryHardening } },
        @{ Name = "SMB Hardening"; Action = { Set-SMBHardening } },
        @{ Name = "NTLM Hardening"; Action = { Set-NTLMHardening } },
        @{ Name = "Network Hardening"; Action = { NetHarden } },
        @{ Name = "Unauthorized File Search"; Action = { Search-UnauthorizedFiles } },
        @{ Name = "Summary"; Action = { Summary } },
        @{ Name = "Run All Hardening Modules"; Action = { param($u,$a) Run-AllModules -Users $u -Admins $a } }
    )

    do {
        Write-Host ""
        Write-Host "Choose which module to run:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $modules.Count; $i++) {
            Write-Host ("[{0}] {1}" -f ($i + 1), $modules[$i].Name) -ForegroundColor Cyan
        }
        Write-Host "[A] Run all modules" -ForegroundColor Cyan
        Write-Host "[Q] Quit" -ForegroundColor Cyan

        $choice = (Read-Host "Enter your selection").Trim()

        switch ($choice.ToUpper()) {
            "A" {
                Run-AllModules -Users $UserList -Admins $AdminList
                return
            }
            "Q" {
                Write-Host "Exiting module menu." -ForegroundColor Yellow
                return
            }
            default {
                if ($choice -match '^[0-9]+$') {
                    $index = [int]$choice - 1
                    if ($index -ge 0 -and $index -lt $modules.Count) {
                        $module = $modules[$index]
                        if ($module.Name -eq "User and Admin Management") {
                            & $module.Action $UserList $AdminList
                        }
                        elseif ($module.Name -eq "Run All Hardening Modules") {
                            & $module.Action $UserList $AdminList
                        }
                        else {
                            & $module.Action
                        }

                        $runAgain = Read-Host "Run another module? (Y/N)"
                        if ($runAgain -notmatch '^(Y|YES)$') {
                            return
                        }
                    }
                    else {
                        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "Invalid selection. Please try again." -ForegroundColor Red
                }
            }
        }
    } while ($true)
}

try {
    Write-Log "Script version: $ScriptVersion"
    Write-Log "Configuration files: User=$UserConfigPath, Admin=$AdminConfigPath"

    $UserList = Read-ConfigFile -FilePath $UserConfigPath -ConfigType "User"
    $AdminList = Read-ConfigFile -FilePath $AdminConfigPath -ConfigType "Admin"

    if ($UserList.Count -eq 0 -and $AdminList.Count -eq 0) {
        Write-Log "No user or admin entries were found in the configuration files. Review the files and rerun the script." "WARNING"
    }

    Show-ModuleMenu
}
catch {
    Write-Log "Critical error during hardening: $_" "ERROR"
    Write-Host "Critical error occurred. Check log file: $HardeningLog" -ForegroundColor Red
    exit 1
}
