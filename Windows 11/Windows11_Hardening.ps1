# Windows 11 Pro CyberPatriot Round 2 hardening helper
# Run from an elevated Windows PowerShell 5.1 session. Review the README/scoring report first.
# This script does NOT install updates, change authorized passwords, delete user profiles,
# change date/time/time zone, disable RDP or CCS, or automatically uninstall software.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:LogFile = $null
$script:TranscriptStarted = $false

# The lists below are sourced from the supplied Round 2 README. Do not put passwords here.
$script:AuthorizedAdmins = @('pparker','tstark','ppotts','hhogan','nfury','mhill','pcoulson')
$script:AuthorizedUsers  = @('bbanner','swilson','sstrange','slang','cdanvers','okoye','kbishop','ybelova','jfoster','nleeds','mjwatson','jtorres','pcarter')
$script:BuiltInAccounts = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')

function Write-Log {
    param([Parameter(Mandatory=$true)][string]$Message, [ValidateSet('INFO','SUCCESS','WARN','ERROR','ACTION')][string]$Level = 'INFO')
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -ErrorAction Stop }
        catch { Write-Host "CRITICAL: could not write to log file: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Invoke-Logged {
    param([Parameter(Mandatory=$true)][string]$Description, [Parameter(Mandatory=$true)][scriptblock]$Action)
    Write-Log "Starting: $Description" 'ACTION'
    try {
        & $Action
        Write-Log "Completed: $Description" 'SUCCESS'
        return $true
    }
    catch {
        Write-Log "FAILED: $Description -- $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Invoke-NativeLogged {
    param([Parameter(Mandatory=$true)][string]$Description, [Parameter(Mandatory=$true)][scriptblock]$Command)
    Write-Log "Starting: $Description" 'ACTION'
    try {
        $output = & $Command 2>&1
        $exitCode = $LASTEXITCODE
        foreach ($line in @($output)) { if ($null -ne $line -and "$line".Trim()) { Write-Log "$line" 'INFO' } }
        if ($exitCode -ne 0) { throw "Native command returned exit code $exitCode" }
        Write-Log "Completed: $Description" 'SUCCESS'
        return $true
    }
    catch { Write-Log "FAILED: $Description -- $($_.Exception.Message)" 'ERROR'; return $false }
}

function Initialize-Logging {
    $candidate = 'C:\Logs'
    try {
        if (-not (Test-Path -LiteralPath $candidate)) { New-Item -ItemType Directory -Path $candidate -Force -ErrorAction Stop | Out-Null }
        $script:LogFile = Join-Path $candidate ('Windows11-Hardening-{0}.log' -f (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))
        New-Item -ItemType File -Path $script:LogFile -Force -ErrorAction Stop | Out-Null
    }
    catch {
        $candidate = Join-Path $PSScriptRoot 'Logs'
        try {
            if (-not (Test-Path -LiteralPath $candidate)) { New-Item -ItemType Directory -Path $candidate -Force -ErrorAction Stop | Out-Null }
            $script:LogFile = Join-Path $candidate ('Windows11-Hardening-{0}.log' -f (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))
            New-Item -ItemType File -Path $script:LogFile -Force -ErrorAction Stop | Out-Null
        }
        catch { Write-Error "Cannot initialize a log file in C:\Logs or $candidate. No changes were made. $($_.Exception.Message)"; exit 2 }
    }
    try {
        Start-Transcript -Path ($script:LogFile -replace '\.log$','.transcript.txt') -Force -ErrorAction Stop | Out-Null
        $script:TranscriptStarted = $true
    }
    catch { Write-Log "Transcript could not start; action log is active: $($_.Exception.Message)" 'WARN' }
    Write-Log "Logging initialized. Log: $script:LogFile" 'INFO'
}

function Set-PolicyValue {
    param([string]$Path,[string]$Name,[object]$Value,[Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::DWord)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Kind -Force -ErrorAction Stop | Out-Null
}

function Set-LocalSecurityPolicy {
    # Export existing settings, preserve them, and add/merge requested account rights.
    $work = Join-Path $env:TEMP ('CP19-SecPolicy-' + [guid]::NewGuid().ToString('N'))
    $cfg = Join-Path $work 'policy.inf'
    $db = Join-Path $work 'policy.sdb'
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    try {
        $export = & secedit.exe /export /cfg $cfg /areas SECURITYPOLICY USER_RIGHTS 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $cfg)) { throw "secedit export failed: $($export -join ' ')" }
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($line in Get-Content -LiteralPath $cfg) { $lines.Add($line) }
        $currentSection = ''
        $rightLines = @{}
        for ($i=0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\s*\[(.+)\]\s*$') { $currentSection = $Matches[1]; continue }
            if ($currentSection -eq 'Privilege Rights' -and $lines[$i] -match '^\s*(Se\w+)\s*=') { $rightLines[$Matches[1]] = $i }
        }
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        $denyEveryone = @('SeDenyNetworkLogonRight')
        $denyGuest = @('SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight','SeDenyNetworkLogonRight','SeDenyBatchLogonRight','SeDenyServiceLogonRight')
        $rightsToAdd = @{}
        if ($guest) {
            $guestSid = $guest.SID.Value
            foreach ($right in $denyGuest) { $rightsToAdd[$right] = @($guestSid) }
        }
        $everyoneSid = 'S-1-1-0'
        foreach ($right in $denyEveryone) {
            if ($rightsToAdd.ContainsKey($right)) { $rightsToAdd[$right] += $everyoneSid }
            else { $rightsToAdd[$right] = @($everyoneSid) }
        }
        foreach ($right in $rightsToAdd.Keys) {
            if ($rightLines.ContainsKey($right)) {
                $idx = $rightLines[$right]
                $existing = @()
                if ($lines[$idx] -match '=\s*(.*)$') { $existing = @($Matches[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
                $merged = @($existing + $rightsToAdd[$right] | Select-Object -Unique)
                $lines[$idx] = "$right = " + (($merged | ForEach-Object { "*$_" }) -join ',')
            }
            else {
                $sectionIndex = -1
                for ($i=0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*\[Privilege Rights\]\s*$') { $sectionIndex = $i; break } }
                $newLine = "$right = " + (($rightsToAdd[$right] | Select-Object -Unique | ForEach-Object { "*$_" }) -join ',')
                if ($sectionIndex -ge 0) {
                    $insertAt = $sectionIndex + 1
                    while ($insertAt -lt $lines.Count -and $lines[$insertAt] -notmatch '^\s*\[') { $insertAt++ }
                    $lines.Insert($insertAt,$newLine)
                }
                else { $lines.Add('[Privilege Rights]'); $lines.Add($newLine) }
            }
        }
        # Password and lockout policy values from the supplied Round 2 checklist.
        $policyValues = @{
            'MinimumPasswordAge' = '20'; 'MaximumPasswordAge' = '60'; 'MinimumPasswordLength' = '12'
            'PasswordHistorySize' = '5'; 'PasswordComplexity' = '1'; 'ClearTextPassword' = '0'
            'LockoutBadCount' = '5'; 'ResetLockoutCount' = '30'; 'LockoutDuration' = '30'
        }
        $sectionIndex = -1
        for ($i=0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*\[System Access\]\s*$') { $sectionIndex = $i; break } }
        if ($sectionIndex -lt 0) { $lines.Add('[System Access]'); $sectionIndex = $lines.Count - 1 }
        foreach ($key in $policyValues.Keys) {
            $found = $false
            for ($i=$sectionIndex+1; $i -lt $lines.Count -and $lines[$i] -notmatch '^\s*\['; $i++) {
                if ($lines[$i] -match ('^\s*' + [regex]::Escape($key) + '\s*=')) { $lines[$i] = "$key = $($policyValues[$key])"; $found = $true; break }
            }
            if (-not $found) {
                $insertAt = $sectionIndex + 1
                while ($insertAt -lt $lines.Count -and $lines[$insertAt] -notmatch '^\s*\[') { $insertAt++ }
                $lines.Insert($insertAt,"$key = $($policyValues[$key])")
                # Keep the section index valid for the next insert.
            }
        }
        Set-Content -LiteralPath $cfg -Value $lines -Encoding Unicode -ErrorAction Stop
        $configure = & secedit.exe /configure /db $db /cfg $cfg /areas SECURITYPOLICY USER_RIGHTS 2>&1
        if ($LASTEXITCODE -ne 0) { throw "secedit configure failed: $($configure -join ' ')" }
        foreach ($line in @($configure)) { if ("$line".Trim()) { Write-Log "$line" 'INFO' } }
        Write-Log 'Local password, lockout, Guest-deny and Everyone network-deny settings applied (existing user-right assignments preserved).' 'SUCCESS'
    }
    finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

function Manage-Accounts {
    Write-Log 'Account policy: README allowlists are embedded; no authorized password will be changed.' 'INFO'
    $currentName = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\')[-1]
    $allowed = @($script:AuthorizedAdmins + $script:AuthorizedUsers | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
    $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop

    # Promote only the README-authorized admins; demote non-authorized local accounts first.
    foreach ($member in $admins) {
        $shortName = ($member.Name -split '[\\/]')[-1]
        if ($script:AuthorizedAdmins -notcontains $shortName) {
            $local = Get-LocalUser -Name $shortName -ErrorAction SilentlyContinue
            if ($local) {
                if ($shortName -ieq $currentName) { Write-Log "Safety hold: current account '$shortName' is unauthorized in the list and was not demoted or removed." 'ERROR'; continue }
                Invoke-Logged "Demote unauthorized administrator '$shortName' before account removal" { Remove-LocalGroupMember -Group 'Administrators' -Member $shortName -ErrorAction Stop }
            }
            else { Write-Log "Administrators contains non-local/unresolved member '$($member.Name)'; left unchanged for manual review." 'WARN' }
        }
    }
    foreach ($name in $script:AuthorizedAdmins) {
        $local = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if (-not $local) { Write-Log "Authorized administrator account is missing: $name (add it manually only if required by the image)." 'WARN'; continue }
        $isMember = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object { (($_.Name -split '[\\/]')[-1]) -ieq $name }
        if (-not $isMember) { Invoke-Logged "Add authorized administrator '$name' to Administrators" { Add-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction Stop } }
        if (-not $local.Enabled) { Invoke-Logged "Enable authorized administrator '$name'" { Enable-LocalUser -Name $name -ErrorAction Stop } }
        Invoke-Logged "Require a password and allow password changes for authorized administrator '$name' (password unchanged)" { Set-LocalUser -Name $name -PasswordNeverExpires $false -UserMayChangePassword $true -ErrorAction Stop }
    }
    foreach ($name in $script:AuthorizedUsers) {
        $local = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if (-not $local) { Write-Log "Authorized user account is missing: $name (add it manually only if required by the image)." 'WARN'; continue }
        if (-not $local.Enabled) { Invoke-Logged "Enable authorized standard user '$name'" { Enable-LocalUser -Name $name -ErrorAction Stop } }
        $isMember = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object { (($_.Name -split '[\\/]')[-1]) -ieq $name }
        if ($isMember) { Invoke-Logged "Demote authorized standard user '$name'" { Remove-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction Stop } }
        Invoke-Logged "Require a password and allow password changes for authorized user '$name' (password unchanged)" { Set-LocalUser -Name $name -PasswordNeverExpires $false -UserMayChangePassword $true -ErrorAction Stop }
    }

    # Remove non-allowlisted local accounts only after the administrator demotion pass.
    foreach ($local in @(Get-LocalUser)) {
        $name = $local.Name
        if ($allowed -contains $name.ToLowerInvariant() -or $script:BuiltInAccounts -contains $name) { continue }
        if ($name -ieq $currentName) { Write-Log "Safety hold: refusing to delete the currently logged-in account '$name'." 'ERROR'; continue }
        $member = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object { (($_.Name -split '[\\/]')[-1]) -ieq $name }
        if ($member) {
            Invoke-Logged "Demote unauthorized administrator '$name' before deletion" { Remove-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction Stop }
        }
        Invoke-Logged "Delete unauthorized local account '$name' (profile/files are intentionally preserved)" { Remove-LocalUser -Name $name -ErrorAction Stop }
    }
    foreach ($name in $script:BuiltInAccounts) {
        $local = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($local -and $local.Enabled) { Invoke-Logged "Disable built-in account '$name'" { Disable-LocalUser -Name $name -ErrorAction Stop } }
    }
    Write-Log 'Account management complete. Authorized passwords were not reset or logged.' 'SUCCESS'
}

function Set-Firewall {
    Invoke-Logged 'Enable Windows Firewall and set default inbound=Block/outbound=Allow for all profiles' {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen $true -ErrorAction Stop
        $verified = Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop
        foreach ($profile in $verified) {
            if (-not $profile.Enabled -or $profile.DefaultInboundAction -ne 'Block' -or $profile.DefaultOutboundAction -ne 'Allow') { throw "Firewall verification failed for $($profile.Name)" }
            Write-Log "Verified $($profile.Name): enabled=$($profile.Enabled), inbound=$($profile.DefaultInboundAction), outbound=$($profile.DefaultOutboundAction)" 'INFO'
        }
    }
    # Preserve the README-required Remote Desktop service and explicitly enable its inbound rules.
    Invoke-Logged 'Keep Remote Desktop enabled and permit its built-in firewall rules' {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord -ErrorAction Stop
        $rdpRules = @(Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue)
        if ($rdpRules.Count -eq 0) { throw 'No Remote Desktop firewall rule group found; enable it manually and verify RDP access.' }
        $rdpRules | Enable-NetFirewallRule -ErrorAction Stop
        Write-Log "Enabled $($rdpRules.Count) built-in Remote Desktop firewall rules; inbound default remains Block." 'INFO'
    }
}

function Set-Defender {
    Invoke-Logged 'Enable core Microsoft Defender protections' {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
        Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop
        Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent 1 -ErrorAction Stop
        Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
    }
    Invoke-Logged 'Run Microsoft Defender quick scan' { Start-MpScan -ScanType QuickScan -ErrorAction Stop }
}

function Set-AuditAndPolicy {
    Invoke-NativeLogged 'Enable Success and Failure auditing for all audit categories' { & auditpol.exe /set /category:* /success:enable /failure:enable }
    Invoke-Logged 'Apply local password, account lockout and account-right policy from the Round 2 checklist' { Set-LocalSecurityPolicy }
    Invoke-Logged 'Require Ctrl+Alt+Delete and enable highest UAC prompt behavior' {
        Set-PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableCAD' 0
        Set-PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2
        Set-PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorUser' 0
        Set-PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' 1
    }
    Invoke-Logged 'Disable AutoPlay and AutoRun for all drives' {
        Set-PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
        Set-PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1
    }
    Invoke-Logged 'Disable Remote Assistance while preserving Remote Desktop' {
        Set-PolicyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord -ErrorAction Stop
    }
    Invoke-Logged 'Keep Windows Security / Action Center monitoring enabled' {
        Set-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' 'DisableNotifications' 0
        Set-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled' 0
    }
}

function Set-UpdatesAndNetwork {
    # README prohibits feature updates. Configure automatic quality/security updates only; do not start an update install.
    Invoke-Logged 'Configure Windows Update automatic option 3 without initiating an update or feature upgrade' {
        $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        if (-not (Test-Path $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
        Set-PolicyValue $path 'NoAutoUpdate' 0
        Set-PolicyValue $path 'AUOptions' 3
        Set-PolicyValue $path 'ScheduledInstallDay' 0
    }
    Invoke-Logged 'Disable LLMNR' { Set-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 }
    Invoke-Logged 'Disable NetBIOS over TCP/IP on active physical adapters' {
        $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq 'Up')
        foreach ($adapter in $adapters) {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($adapter.InterfaceGuid.ToString())"
            if (Test-Path $regPath) { Set-ItemProperty -LiteralPath $regPath -Name NetbiosOptions -Value 2 -ErrorAction Stop }
            else { Write-Log "NetBT interface registry key not found for $($adapter.Name); skipped." 'WARN' }
        }
    }
}

function Disable-UnneededComponents {
    foreach ($serviceName in @('RemoteRegistry','DiagTrack','dmwappushservice','MapsBroker')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            Invoke-Logged "Disable service $serviceName" {
                Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
                if ((Get-Service -Name $serviceName).Status -eq 'Running') { Stop-Service -Name $serviceName -Force -ErrorAction Stop }
            }
        }
        else { Write-Log "Optional service not present: $serviceName" 'INFO' }
    }
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq 'Enabled') {
        Invoke-Logged 'Disable optional SMB 1.0/CIFS feature (SMB2/3 are not changed)' { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null }
    }
}

function Set-SmbSecurity {
    Invoke-Logged 'Require SMB signing for the server and workstation' {
        Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force -ErrorAction Stop
        Set-SmbClientConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force -ErrorAction Stop
    }
}

function Report-ManualItems {
    Write-Log 'Manual review items (no automatic changes made):' 'INFO'
    Write-Log 'Check the CyberPatriot Scoring Report and Windows Security/Protection History; update approved applications only.' 'INFO'
    Write-Log 'Verify Chrome is the default browser in Windows Settings; Windows does not support safely forcing all default associations by a simple registry edit.' 'INFO'
    Write-Log 'Review installed applications, startup entries, scheduled tasks, shares, and unauthorized files against the README; this script does not uninstall software or delete user files.' 'INFO'
    Write-Log 'No Windows feature update, Insider build, date/time/time-zone change, or system recovery action was attempted.' 'INFO'
}

Initialize-Logging
try {
    Write-Log 'CyberPatriot Windows 11 Pro Round 2 hardening started.' 'INFO'
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log 'Must be run from an elevated PowerShell session. No hardening changes were made.' 'ERROR'
        exit 1
    }
    Write-Host 'This will enforce the supplied README account allowlist, remove unauthorized local accounts after demoting them, and leave authorized passwords unchanged.' -ForegroundColor Yellow
    Write-Host 'RDP stays enabled. Firewall defaults will be inbound Block and outbound Allow; the built-in RDP inbound rules remain enabled.' -ForegroundColor Yellow
    Write-Host "All attempted changes and errors are recorded in $script:LogFile and the transcript." -ForegroundColor Cyan
    $confirm = Read-Host 'Type APPLY to continue, or anything else to quit'
    if ($confirm -cne 'APPLY') { Write-Log 'User cancelled before changes.' 'WARN'; return }

    # Account operation is intentionally first: unauthorized admin memberships are removed before accounts.
    Invoke-Logged 'Reconcile local user/admin accounts using the supplied README allowlist' { Manage-Accounts }
    Set-Firewall
    Set-Defender
    Set-AuditAndPolicy
    Set-UpdatesAndNetwork
    Set-SmbSecurity
    Disable-UnneededComponents
    Report-ManualItems
    Write-Log 'Hardening run completed. Review the log and CyberPatriot scoring report; reboot may be needed for some policy changes.' 'SUCCESS'
}
catch {
    Write-Log "Unhandled script failure: $($_.Exception.Message)" 'ERROR'
    Write-Log 'Execution stopped after the failure; review the log to see which actions were already applied.' 'ERROR'
}
finally {
    if ($script:TranscriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
    if ($script:LogFile) { Write-Host "Action log: $script:LogFile" -ForegroundColor Cyan }
}
