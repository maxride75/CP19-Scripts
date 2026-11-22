Windows 11 Image Competition Checklist

During Windows 11 image:

1. Browser Update the web browser (usually firefox or chrome), make it the default browser, and uninstall any other browsers if the README specifies to do so
1. Misc Update all approved software in the README. You will usually have to go to the software’s website and download it, but make sure to check where it is installed before installing it. Notable exceptions to the website rule, if late enough, are Notepad++ and Wireshark, where they can auto download their own updates.
1. Windows Security, Resolve any warnings about security, enable windows firewall, check protection history and exceptions, update windows security, and run a quick scan, and make sure the firewall rules are block incoming, and allow outgoing traffic.
1. Windows Update If the README doesn’t say not to update the computer, manually check for updates, and check for auto update policies. If they exist, take a note of it, this will be fixed in step 15b. 
1. Apps > Startup, Task Manager, and/or Task Scheduler check for any bad startup apps, and disable any bad ones. If in Scheduler, the job is connected to a non-existent app, it is fine to leave there.
1. System > About > Advanced System Settings > Remote Tab Uncheck the Remote Assistance checkbox. If the README specifies needing Remote Desktop, set the option to Allow, and check the box for network-level authentication, or set the option to Don’t Allow
1. Control Panel > Programs > Programs and Features Uninstall any programs that the README does not say to keep (uninstall any unrecognized programs). Make sure to check the README before uninstalling anything, specifically Wireshark because Wireshark is sometimes needed as stated in the README.
1. Turn Windows features on or off Turn off any features that you think shouldn't be there, or is not stated in the README. (TCP port sharing in .NET advanced services, SMB file sharing/SMBv1 if SMB is alllowed, etc.). If a feature that has a corresponding service was turned off here, take note of it and make sure to check for it specifically in step 14.
1. User Accounts > User Accounts Manage another account Delete unauthorized users, demote users not supposed to be admin, make sure everybody has a password, and change insecure admin passwords, disable password never expires, user cannot change password
1. Security > Change UAC settings Set the slider to the highest setting
1. Autoplay Fully turn it off! Also check in Settings as that also has autoplay settings to turn off.
1. MMC > Computer Management > Local Users and Groups Add any users that need to be added to groups to groups (add the group if necessary), if README dictates users’ password needs to expire, go through each user and enable password expiration
1. MMC > Computer Management > Services check for any bad services (main suspects are Microsoft FTP service, World Wide Web Publishing Service,  Simple Mail Transfer Protocol (SMTP) Simple TCP/IP Services,etc)
1. If SMB is required in the README, check for any shares that shouldn’t be there (the default shares are ADMIN$, C$, and IPC$, any others you should delete unless the README specifies). 
1. In Password Policy, set these options: Password History = 5, Max Age = 60, Min Age = 20, Min Length = 12, Min Password Audit = 12, Pwd meets complexity requirements = enabled, = relax min pwd length limit = disabled, pwd reversible encryption = disabled
1. In Account Lockout Policy set these rules: account lock threshold = 5, Lockout Duration=30min, reset lockout counter after=30min, Admin lockout=enabled
1. In Audit Policy, set all options to both Success and Failure
1. In Security Options, set Interactive Login: Do not require CTRL-ALT-DEL to disabled, 
1. Network Access: Do not allow anonymous enumeration of SAM accounts and shares to enabled, 
1. Network Access: Limit local use of blank passwords to console only to enabled
1. Network access: Restrict anonymous access to Named Pipes and Shares -> Set to Enabled.
1. Network access: Let Everyone permissions apply to anonymous users -> Set to Disabled.
1. Network Server & Client Digitally sign communications (always) -> Set to On
1. Auto Update -> Set to either option 3 or 4
1. Make sure the group Everyone can’t login over the network, and the Guest account can’t log in anywhere.
1. Disable the Guest, Administrator, DefaultAccount, WDAGUtiltyAccount accounts
1. Task Scheduler Check to make sure that nothing malicious is started on login/startup!
