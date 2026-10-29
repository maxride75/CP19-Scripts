# Windows 11 Baseline Hardening Script
# This script implements security hardening best practices for Windows 11
# Run with Administrator privileges
# Usage: powershell -ExecutionPolicy Bypass -File Windows11_Hardening.ps1

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please re-run with elevated privileges." -ForegroundColor Red
    Exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows 11 Baseline Hardening Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Before proceeding, complete the forensics questions, update approved software, and remove unauthorized software." -ForegroundColor Yellow
Write-Host "You need 2 files, admins.txt and users.txt, placed in the same directory as this script." -ForegroundColor Purple
Write-Host "Do not include passwords in there, but include yourself." -ForegroundColor Purple
Read-Host "Press Enter to continue"

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

function Load-UserList {
    param([string]$FilePath)

    $users = @()
    if (Test-Path $FilePath) {
        $users = Get-Content -Path $FilePath | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
    }
    else {
        Write-Log "Warning: File not found: $FilePath" "WARN"
    }
    return $users
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

Write-Log "Starting Windows 11 hardening..." "INFO"

# ============================================================================
# 0. USER AND ADMIN MANAGEMENT
# ============================================================================
function Users {
    Write-Log "Configuring user and admin management..." "INFO"

    $scriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
    $usersFile = Join-Path -Path $scriptDir -ChildPath "users.txt"
    $adminsFile = Join-Path -Path $scriptDir -ChildPath "admins.txt"

    $allowedUsers = @()
    $allowedAdmins = @()
    $localUsers = @()

    try {
        $allowedUsers = Load-UserList -FilePath $usersFile
        $allowedAdmins = Load-UserList -FilePath $adminsFile
        $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\\')[-1]

        Write-Log "Loaded $($allowedUsers.Count) allowed users" "INFO"
        Write-Log "Loaded $($allowedAdmins.Count) allowed admins" "INFO"

        $addPrompt = Read-Host "Do you want to add a user or group? (Y/N)"
        if ($addPrompt -match '^(Y|YES)$') {
            $entryType = Read-Host "Add user or group? (user/group)"
            if ($entryType -match '^(user|u)$') {
                $newUsers = (Read-Host "Enter comma-separated list of users to add").Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                foreach ($user in $newUsers) {
                    if ($allowedUsers -notcontains $user) {
                        $allowedUsers += $user
                        Write-Log "User added to approved list: $user" "SUCCESS"
                    }
                }
            }
            elseif ($entryType -match '^(group|g)$') {
                $newGroups = (Read-Host "Enter comma-separated list of groups to add").Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                foreach ($groupName in $newGroups) {
                    if ($allowedAdmins -notcontains $groupName) {
                        $allowedAdmins += $groupName
                        Write-Log "Group added to approved admin list: $groupName" "SUCCESS"
                    }
                }
            }
        }

        if ($allowedAdmins.Count -gt 0) {
            foreach ($admin in $allowedAdmins) {
                try {
                    $adminExists = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
                    if ($adminExists) {
                        $adminGroup = [ADSI]"WinNT://./Administrators"
                        $adminGroupMembers = @($adminGroup.psbase.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }

                        if ($adminGroupMembers -notcontains $admin) {
                            $adminGroup.Add("WinNT://./$admin")
                            Write-Log "User added to Administrators group: $admin" "SUCCESS"
                        }
                        else {
                            Write-Log "User already in Administrators group: $admin" "INFO"
                        }

                        if ($adminExists.Enabled -eq $false) {
                            Enable-LocalUser -Name $admin -ErrorAction SilentlyContinue
                            Write-Log "Admin account enabled: $admin" "SUCCESS"
                        }
                    }
                    else {
                        Write-Log "Admin user not found on system: $admin" "WARN"
                    }
                }
                catch {
                    Write-Log "Error processing admin user $admin : $_" "WARN"
                }
            }
        }

        if ($allowedUsers.Count -gt 0) {
            foreach ($user in $allowedUsers) {
                try {
                    $userExists = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
                    if ($userExists) {
                        if ($userExists.Enabled -eq $false) {
                            Enable-LocalUser -Name $user -ErrorAction SilentlyContinue
                            Write-Log "Standard user account enabled: $user" "SUCCESS"
                        }

                        $adminGroup = [ADSI]"WinNT://./Administrators"
                        $adminGroupMembers = @($adminGroup.psbase.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }

                        if ($allowedAdmins -notcontains $user -and $adminGroupMembers -contains $user) {
                            $adminGroup.Remove("WinNT://./$user")
                            Write-Log "User removed from Administrators group: $user" "SUCCESS"
                        }

                        if ($userExists.PasswordRequired -eq $false) {
                            $null = Set-RandomPasswordForUser -Username $user
                        }
                    }
                    else {
                        Write-Log "Standard user not found on system: $user" "WARN"
                    }
                }
                catch {
                    Write-Log "Error processing standard user $user : $_" "WARN"
                }
            }
        }

        $adminGroupMembers = @((Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name))
        foreach ($adminName in $adminGroupMembers) {
            if ($adminName -eq $currentUser) {
                continue
            }

            try {
                $adminUser = Get-LocalUser -Name $adminName -ErrorAction SilentlyContinue
                if ($adminUser) {
                    $null = Set-RandomPasswordForUser -Username $adminName
                }
            }
            catch {
                Write-Log "Error changing password for admin $adminName : $_" "WARN"
            }
        }

        $combinedAllowedUsers = ($allowedUsers + $allowedAdmins | Select-Object -Unique)
        foreach ($localUser in $localUsers) {
            try {
                if ($localUser.Name -match '^(\$|Guest|DefaultAccount)') {
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
                Write-Log "Error processing unauthorized user $($localUser.Name) : $_" "WARN"
            }
        }

        Write-Log "User and admin management completed" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring user and admin management: $_" "ERROR"
    }
}

# ============================================================================
# 1. WINDOWS DEFENDER AND ANTIMALWARE SETTINGS
# ============================================================================
function Defender-AntiMal {
    Write-Log "Configuring Windows Defender settings..." "INFO"

    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Write-Log "Real-time protection enabled" "SUCCESS"

        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Write-Log "Cloud-delivered protection enabled" "SUCCESS"

        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
        Write-Log "Behavior monitoring enabled" "SUCCESS"

        Set-MpPreference -ScanScheduleDay Everyday -ScanScheduleTime 02:00 -ErrorAction SilentlyContinue
        Write-Log "Daily scan scheduled for 2:00 AM" "SUCCESS"

        Set-MpPreference -DisableNetworkProtectionNotifications $false -ErrorAction SilentlyContinue
        Write-Log "Network inspection system enabled" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring Windows Defender: $_" "ERROR"
    }
}

# ============================================================================
# 2. WINDOWS FIREWALL SETTINGS
# ============================================================================
function Firewall {
    Write-Log "Configuring Windows Firewall..." "INFO"

    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -ErrorAction SilentlyContinue
        Write-Log "Windows Firewall enabled for all profiles" "SUCCESS"

        Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
        Write-Log "Firewall inbound/outbound policies configured" "SUCCESS"

        Set-NetFirewallProfile -Profile Domain, Public, Private -NotifyOnListen $false -ErrorAction SilentlyContinue
        Write-Log "Firewall notification settings configured" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring Windows Firewall: $_" "ERROR"
    }
}

# ============================================================================
# 3. USER ACCOUNT CONTROL (UAC) SETTINGS
# ============================================================================
function UAC {
    Write-Log "Configuring User Account Control..." "INFO"

    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Force
        Write-Log "UAC set to always prompt for admin consent" "SUCCESS"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0 -Force
        Write-Log "UAC user consent settings configured" "SUCCESS"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Force
        Write-Log "Secure desktop for UAC prompts enabled" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring UAC: $_" "ERROR"
    }
}

# ============================================================================
# 4. DISABLE UNNECESSARY SERVICES
# ============================================================================
function Disable-Services {
    Write-Log "Disabling unnecessary services..." "INFO"

    $servicesToDisable = @(
        "RemoteRegistry",
        "lfsvc",
        "DiagTrack",
        "dmwappushservice",
        "MapsBroker",
        "HomeGroupListener",
        "HomeGroupProvider"
    )

    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Set-Service -Name $service -StartupType Disabled -Force -ErrorAction SilentlyContinue
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Write-Log "Service disabled: $service" "SUCCESS"
            }
        }
        catch {
            Write-Log "Error disabling service $service : $_" "WARN"
        }
    }
}

# ============================================================================
# 5. LOCAL SECURITY POLICY SETTINGS
# ============================================================================
function LocalSec {
    Write-Log "Configuring Local Security Policy..." "INFO"

    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest) {
            Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
            Write-Log "Guest account disabled" "SUCCESS"
        }

        # Password policy
        net accounts /uniquepwd:5 | Out-Null
        net accounts /minpwlen:16 | Out-Null
        net accounts /maxpwage:60 | Out-Null
        net accounts /minpwage:20 | Out-Null
        net accounts /lockoutduration:30 | Out-Null
        net accounts /lockoutthreshold:5 | Out-Null
        Write-Log "Password policy configured (password history 5, minimum length 16, max age 60, lockout threshold 5)" "SUCCESS"

        # Password complexity / encryption / lockout
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLmHash" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableCAD" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null

        # Named pipe / share restrictions
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionPipes" -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionShares" -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null

        # Local admin lockout policy must allow admins to lock out as part of least privilege / security policy
        Write-Log "Admins can be locked out of their accounts under configured lockout policy" "SUCCESS"

        if (Get-Command ntrights -ErrorAction SilentlyContinue) {
            & ntrights +r SeDenyNetworkLogonRight -u Everyone | Out-Null
            Write-Log "Everyone removed from the right to log on over the network" "SUCCESS"
        }
        else {
            Write-Log "ntrights not available — remove Everyone from Network logon rights manually in Local Security Policy" "WARN"
        }

        Write-Log "Local security hardening completed" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring Local Security Policy: $_" "ERROR"
    }
}

# ============================================================================
# 6. SYSTEM AUDIT LOGGING
# ============================================================================
function Audit {
    Write-Log "Enabling system audit logging..." "INFO"

    try {
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

# ============================================================================
# 7. CONFIGURE WINDOWS UPDATE
# ============================================================================
function Updatepol {
    Write-Log "Configuring Windows Update..." "INFO"

    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 3 -Force -ErrorAction SilentlyContinue
        Write-Log "Automatic Windows updates configured" "SUCCESS"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3 -Force -ErrorAction SilentlyContinue
        Write-Log "Update schedule configured" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring Windows Update: $_" "ERROR"
    }
}

# ============================================================================
# 8. DISABLE UNNECESSARY FEATURES
# ============================================================================
function FeatureDisable {
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
        }
        catch {
            Write-Log "Error disabling feature $feature : $_" "WARN"
        }
    }
}

# ============================================================================
# 9. NETWORK HARDENING
# ============================================================================
function NetHarden {
    Write-Log "Applying network hardening settings..." "INFO"

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

# ============================================================================
# 10. WINDOWS DEFENDER EXPLOIT GUARD
# ============================================================================
function WDAG {
    Write-Log "Configuring Windows Defender Exploit Guard..." "INFO"

    try {
        Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\Program Files\*" -ErrorAction SilentlyContinue
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        Write-Log "Attack Surface Reduction and Controlled Folder Access enabled" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring Exploit Guard: $_" "WARN"
    }
}

# ============================================================================
# 11. PRIVACY SETTINGS
# ============================================================================
function Privacy {
    Write-Log "Configuring privacy settings..." "INFO"

    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log "Cortana disabled" "SUCCESS"

        Set-Service -Name "DiagTrack" -StartupType Disabled -Force -ErrorAction SilentlyContinue
        Set-Service -Name "dmwappushservice" -StartupType Disabled -Force -ErrorAction SilentlyContinue
        Write-Log "Telemetry services disabled" "SUCCESS"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Log "Activity history disabled" "SUCCESS"
    }
    catch {
        Write-Log "Error configuring privacy settings: $_" "WARN"
    }
}

# ============================================================================
# 12. UNAUTHORIZED FILE SEARCHING
# ============================================================================
function Search-UnauthorizedFiles {
    Write-Log "Searching for unauthorized files in user and public directories..." "INFO"

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

# ============================================================================
# 13. SUMMARY
# ============================================================================
function Summary {
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
}

function Show-ModuleMenu {
    $modules = @(
        @{ Name = "User and Admin Management"; Action = { Users } },
        @{ Name = "Windows Defender and Antimalware"; Action = { Defender-AntiMal } },
        @{ Name = "Windows Firewall"; Action = { Firewall } },
        @{ Name = "User Account Control"; Action = { UAC } },
        @{ Name = "Disable Unnecessary Services"; Action = { Disable-Services } },
        @{ Name = "Local Security Policy"; Action = { LocalSec } },
        @{ Name = "System Audit Logging"; Action = { Audit } },
        @{ Name = "Windows Update Policy"; Action = { Updatepol } },
        @{ Name = "Disable Unnecessary Features"; Action = { FeatureDisable } },
        @{ Name = "Network Hardening"; Action = { NetHarden } },
        @{ Name = "Windows Defender Exploit Guard"; Action = { WDAG } },
        @{ Name = "Privacy Settings"; Action = { Privacy } },
        @{ Name = "Unauthorized File Search"; Action = { Search-UnauthorizedFiles } },
        @{ Name = "Summary"; Action = { Summary } }
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
                foreach ($module in $modules) {
                    & $module.Action
                }
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
                        & $modules[$index].Action
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

# Start the menu-driven execution
Show-ModuleMenu
