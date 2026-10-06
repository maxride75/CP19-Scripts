#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="${0##*/}"
readonly LOG_FILE="/var/log/${SCRIPT_NAME%.sh}.log"

TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
HOME_DIR="/home/${TARGET_USER}"

log() {
    printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "${LOG_FILE}" >&2
}

warn() {
    log "WARN: $*"
}

err() {
    log "ERROR: $*" >&2
    exit 1
}

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        echo "Error: This script must be run as root or with sudo." >&2
        exit 1
    fi
}

prompt_yes_no() {
    local prompt="$1"
    local answer=""

    while true; do
        read -r -p "${prompt} (y/n): " answer || answer="n"
        case "${answer,,}" in
            y|yes)
                return 0
                ;;
            n|no)
                return 1
                ;;
            *)
                echo "Invalid response. Please enter y or n."
                ;;
        esac
    done
}

prompt_choice() {
    local prompt="$1"
    local valid_options="$2"
    local input=""

    while true; do
        read -r -p "${prompt} " input || input=""
        if [[ " ${valid_options} " == *" ${input} "* ]]; then
            printf '%s' "${input}"
            return 0
        fi
        echo "Invalid response. Valid options: ${valid_options}"
    done
}

ensure_file_exists() {
    local path="$1"
    if [[ ! -f "${path}" ]]; then
        err "Required file not found: ${path}"
    fi
}

set_config_value() {
    local file_path="$1"
    local key="$2"
    local value="$3"

    [[ -f "${file_path}" ]] || touch "${file_path}"

    if grep -Eq "^${key}[[:space:]]+" "${file_path}"; then
        sed -i "s|^${key}[[:space:]].*|${key} ${value}|" "${file_path}"
    else
        printf '%s %s\n' "${key}" "${value}" >> "${file_path}"
    fi
}

write_pam_file() {
    local path="$1"
    local content="$2"
    printf '%s\n' "${content}" > "${path}"
}

forensics() {
	if prompt_yes_no "Have the forensics questions been answered or are they answerable?"; then
		echo "Nice job!"
	else
        echo "Forensics help is in /home/$TARGET_USER/forensics.txt, but help can also be found by googling..."
		echo "------FORENSICS HELP-------" > forensics.txt
		echo "sha256sum _file_ for a SHA256 filehash" >> forensics.txt
		echo "md5sum _file_ for a MD5 filehash" >> forensics.txt
		echo "steghide extract -p _password_ -sf _file_" >> forensics.txt
		echo "locate '*.filetype' for finding music files" >> forensics.txt
		echo "Crontab jobs are in /etc/crontab, which will have the actual location of the job." >> forensics.txt
		echo "ss -tlnp or (once nmap is installed) nmap -sT localhost shows open ports, and then top -p _PID_ can be used to find and stop a task" >> forensics.txt
		echo "For ciphers, use dcode.fr to solve them." >> forensics.txt
		echo "To find a specific file as part of the question, use locate _file_ to find it." >> forensics.txt
		echo "Use base64 -d to decode a base64-encrypted message." >> forensics.txt
		echo "Take a look at it if you need help!"
    fi
    read -p "Press [Enter] to continue... "
    
}

update() {
    if prompt_yes_no "Does the README specify not to update packages?"; then
        echo "Update manually as required by the README."
    else
        echo "Proceeding with package updates..."
        apt update -y >/dev/null
        apt list --upgradable > "${HOME_DIR}/upgraded_pkgs.txt" 2>/dev/null || true
        apt upgrade -y >/dev/null || warn "Package upgrade returned a non-zero exit code."
        echo "Check for packages installed via Mint Store and uninstall anything that is not approved."
    fi
    read -p "Press [Enter} to continue... "
}
install_packages() {
    log "Installing required packages..."
    apt update -y >/dev/null
    apt install -y ufw stacer pwgen libpam-pwquality clamav clamav-daemon nmap rtkithunter unix-privesc-check >/dev/null || warn "Packages were not installed successfully!"
}

configure_firewall() {
    log "Enabling UFW firewall..."
    ufw --force enable >/dev/null || warn "UFW enable command returned non-zero; check status manually."
}

configure_pam() {
    log "Configuring PAM faillock policies..."
    mkdir -p /usr/share/pam-configs

    write_pam_file "/usr/share/pam-configs/faillock" "Name: Enforce failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
[default=die] pam_faillock.so authfail
sufficient pam_faillock.so authsucc"

    write_pam_file "/usr/share/pam-configs/faillock_notify" "Name: Notify on failed login attempts
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
requisite pam_faillock.so preauth"

    write_pam_file "/usr/share/pam-configs/faillock_reset" "Name: Reset lockout on success
Default: no
Priority: 0
Auth-Type: Additional
Auth:
required pam_faillock.so authsucc"

    echo "PAM modules have been created. Please enable them with pam-auth-update."
    read -r -p "Press [Enter] to continue once pam-auth-update is done..." </dev/tty
}

check_and_manage_admins() {
    log "Reviewing local admin accounts..."

    if [[ ! -f "${HOME_DIR}/admins.txt" ]]; then
        warn "${HOME_DIR}/admins.txt not found. Create it with the approved admin list before continuing."
        return 0
    fi

    groupmems -g sudo -l > "${HOME_DIR}/machineadmins.txt" 2>/dev/null || true
    sort -o "${HOME_DIR}/admins.txt" "${HOME_DIR}/admins.txt"
    sort -o "${HOME_DIR}/machineadmins.txt" "${HOME_DIR}/machineadmins.txt"

    diff --changed-group-format='%<' --unchanged-group-format='' \
        "${HOME_DIR}/machineadmins.txt" "${HOME_DIR}/admins.txt" > "${HOME_DIR}/maybebadadmins.txt" || true

    if [[ -s "${HOME_DIR}/maybebadadmins.txt" ]]; then
        echo "Potentially bad admins:"
        cat "${HOME_DIR}/maybebadadmins.txt"
        if prompt_yes_no "Would you like to demote the suspect admins?"; then
            while IFS= read -r admin; do
                [[ -z "${admin}" ]] && continue
                echo "Demoting user: ${admin}"
                deluser "${admin}" sudo || warn "Failed to demote ${admin}"
            done < "${HOME_DIR}/maybebadadmins.txt"
        else
            echo "Make sure to demote them for points!"
        fi
    else
        echo "No suspect admins found, but this doesn't mean they aren't there! Manually check for them!"
    fi
}

check_and_manage_users() {
    log "Reviewing local user accounts..."

    if [[ ! -f "${HOME_DIR}/users.txt" ]]; then
        warn "${HOME_DIR}/users.txt not found. Create it with the approved user list before continuing."
        return 0
    fi

    awk -F: '$3 >= 1000 && $3 <= 65534 {print $1}' /etc/passwd > "${HOME_DIR}/machineusers.txt"
    sort -o "${HOME_DIR}/users.txt" "${HOME_DIR}/users.txt"
    sort -o "${HOME_DIR}/machineusers.txt" "${HOME_DIR}/machineusers.txt"

    diff --changed-group-format='%<' --unchanged-group-format='' \
        "${HOME_DIR}/machineusers.txt" "${HOME_DIR}/users.txt" > "${HOME_DIR}/maybebadusers.txt" || true

    if [[ -s "${HOME_DIR}/maybebadusers.txt" ]]; then
        echo "Potentially bad users:"
        cat "${HOME_DIR}/maybebadusers.txt"

        if prompt_yes_no "Would you like to delete the suspect users?"; then
            while IFS= read -r user; do
                [[ -z "${user}" ]] && continue
                echo "Removing user: ${user}"
                userdel -r "${user}" || warn "Failed to remove ${user}"
            done < "${HOME_DIR}/maybebadusers.txt"
        else
            echo "Make sure to delete them for points!"
        fi

    else
        echo "No suspect users found."
    fi
	
	awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -v root > uid0.txt
	if [[ -f "uid0.txt" ]]; then
		echo "USER WITH ROOT PERMS FOUND!!! DEMOTE IMMEDIATELY!!!"
		cat uid0.txt
		if prompt_yes_no "Would you like to change their UID (y/n): "; then
			BADUSER=$(cat uid0.txt)
			killall -u $BADUSER
			usermod -u 3024 $BADUSER
			groupmod -g 3024 $BADUSER
			fi
	fi
	
	
	echo "These users have a UID that is less than 1000, meaning they are hidden"
    awk -F: '$3 < 1000 {print "User: " $1, "UID: " $3, "Shell: " $7}' /etc/passwd > hiddenuser.txt
    echo "Make sure they are authorized, because the script does not scan for hidden users."
	read -p "Press [Enter] to continue... "
}

manage_local_users_and_groups() {
    log "Additional user/group management..."

    while true; do
        local choice
        choice="$(prompt_choice "Does the README require extra user management? (G/U/N): " "G U N")"

        case "${choice}" in
            G)
                if [[ ! -d "${HOME_DIR}/group" ]]; then
                    warn "Group directory not found: ${HOME_DIR}/group"
                    break
                fi
                cd "${HOME_DIR}/group" || err "Unable to enter ${HOME_DIR}/group"
                local group_name
                group_name="$(tr -d '\r' < group.txt)"
                [[ -n "${group_name}" ]] || { warn "group.txt is empty."; break; }
                echo "Making group ${group_name}"
                groupadd "${group_name}" || warn "Group ${group_name} may already exist."
                while IFS= read -r user; do
                    [[ -z "${user}" ]] && continue
                    usermod -aG "${group_name}" "${user}" || warn "Failed to add ${user} to group ${group_name}"
                done < user.txt
                break
                ;;
            U)
                if [[ ! -d "${HOME_DIR}/user" ]]; then
                    warn "User directory not found: ${HOME_DIR}/user"
                    break
                fi
                cd "${HOME_DIR}/user" || err "Unable to enter ${HOME_DIR}/user"
                local user_name
                user_name="$(tr -d '\r' < user.txt)"
                [[ -n "${user_name}" ]] || { warn "user.txt is empty."; break; }
                echo "Making user ${user_name}"
                useradd -m -s /bin/nologin "${user_name}" || warn "User ${user_name} may already exist."
                echo "User ${user_name} made."
                break
                ;;
            N)
                echo "If you need to, use: adduser or usermod -aG group"
                break
                ;;
            *)
                echo "Invalid response."
                ;;
        esac
    done
}
adminpwd() {
    for i in (cat admins.txt); do
        if [[ "$i" != "$TARGET_USER" ]]; then
            echo "$i:$(pwgen -sy 20 1)" | chpasswd
        fi
    done

    }

userpwd() {
    for i in (cat users.txt); do
        if [[ "$i" != "$TARGET_USER" ]]; then
            echo "$i:$(pwgen -sy 20 1)" | chpasswd
        fi
    done
}

configure_login_defs() {
    log "Configuring login.defs password policy..."
    local config_doc="/etc/login.defs"

    set_config_value "${config_doc}" "PASS_MAX_DAYS" "60"
    set_config_value "${config_doc}" "PASS_MIN_DAYS" "20"
    set_config_value "${config_doc}" "PASS_WARN_AGE" "7"
    echo "/etc/login.defs updated successfully."
}

misc_sec() {
    echo "kernel.dmesg_restrict=1" | tee -a /etc/sysctl.d/6-dmesg-sudo.conf >/dev/null

    while IFS= read -r user; do
        [[ -z "${user}" ]] && continue
        if [[ "${user}" != "${TARGET_USER}" ]]; then
            chage -M 60 "${user}" || warn "Failed to set password max age for ${user}"
        fi
    done < <(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)

    echo "All other unhidden users' maximum password age was set to 60 days."
    read -r -p "Check for hidden users now and adjust them manually if needed. Press [Enter] to continue..." </dev/tty
    set_config_value "/etc/sysctl.conf" "net.ipv4.tcp_syncookies" "1"
    set_config_value "/etc/sysctl.conf" "kernel.randomize_va_space" "2"
    sysctl --system >/dev/null || warn "sysctl --system returned a non-zero exit status."
}

configure_ssh() {
    log "Checking SSH settings..."
    if ! prompt_yes_no "Does the README say users need to log in via SSH?"; then
        echo "If SSH is running and not required, stop it with: systemctl stop ssh"
        return 0
    fi

    echo "Securing SSH!"
    local ssh_config="/etc/ssh/sshd_config"
    if [[ ! -f "${ssh_config}" ]]; then
        warn "No sshd_config file found. Skipping SSH hardening."
        return 0
    fi

    set_config_value "${ssh_config}" "PermitRootLogin" "no"
    set_config_value "${ssh_config}" "UsePAM" "yes"
    set_config_value "${ssh_config}" "PermitEmptyPasswords" "no"
    set_config_value "${ssh_config}" "DisableForwarding" "yes"
    set_config_value "${ssh_config}" "MaxAuthTries" "6"
    systemctl reload ssh || warn "Failed to reload SSH service."
}

root_lock() {
    passwd -l root || warn "Failed to lock root account."
}
sysrq() {
	set_config_value "/etc/sysctl.conf" "kernel.sysrq =" "0"
}
reperm_files() {
    cd /etc
    chown root:root sudoers shadow passwd ssh/sshd_config /boot/grub/grub.cfg
    chmod 440 /etc/sudoers
    chmod 600 shadow /boot/grub/grub.cfg ssh/shhd_config 
    chmod 644 passwd
    cd $HOMEDIR
}

easter_egg() {
    curl ascii.live/rick
}

nmap() {
	nmap -sT -o $HOMEDIR/nmap.txt localhost
	echo "This machine's ports have been scanned, ouput is in $HOMEDIR/nmap.txt"
	echo "Take a look, more information can be found at speedguide.net or via ss -tlnp."
	read -p "Press [Enter] to continue... "
}
configure_web_services() {
    local choice
    choice="$(prompt_choice "Is the computer running a service? (Nginx/Apache/FTP/Mysql/X(none)): " "N A F M X")"

    case "${choice}" in
        N)
            echo "Securing nginx!"
            cat > /tmp/nginxconfig.txt <<'EOF'
(single quote is double quote) In /etc/nginx/nginx.conf, in the http block.
Uncomment server_tokens off;
client_body_buffer_size  10K;
client_header_buffer_size 1k;
client_max_body_size     8m;
large_client_header_buffers 2 1k;

In the server block of the file add
add_header X-Frame-Options 'SAMEORIGIN' always;
add_header X-XSS-Protection '1; mode=block' always;
add_header X-Content-Type-Options 'nosniff' always;
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 405;
}
EOF
            echo "The nginx configuration instructions have been saved to /tmp/nginxconfig.txt"
            read -r -p "Add the lines manually to /etc/nginx/nginx.conf, then press [Enter] to continue..." </dev/tty
            nginx -t || warn "nginx config test failed; check the configuration manually."
            systemctl reload nginx || warn "Failed to reload nginx."
            ;;
        A)
            echo "Securing Apache!"
            local sec_conf="/etc/apache2/conf-available/security.conf"
            local apache_conf="/etc/apache2/apache2.conf"
            if [[ -f "${sec_conf}" ]]; then
                set_config_value "${sec_conf}" "ServerTokens" "Prod"
                set_config_value "${sec_conf}" "ServerSignature" "Off"
                set_config_value "${sec_conf}" "TraceEnable" "Off"
            else
                warn "Apache security.conf not found. Skipping Apache hardening."
            fi
            if [[ -f "${apache_conf}" ]]; then
                set_config_value "${apache_conf}" "Options" "-Indexes -FollowSymLinks"
            fi
            read -r -p "Apache has been secured; run apache2ctl configtest and then press [Enter] to continue..." </dev/tty
            systemctl restart apache2 || warn "Apache service restart failed."
            ;;
        F)
            echo "Securing FTP!"
            cat > /tmp/ftpconfig.txt <<'EOF'
anonymous_enable=no
chroot_local_user=yes
EOF
            echo "The FTP configuration lines have been saved to /tmp/ftpconfig.txt"
            read -r -p "Add the FTP config to /etc/vsftpd.conf, then press [Enter] to continue..." </dev/tty
            systemctl restart vsftpd || warn "vsftpd restart failed."
            ;;
        M)
            echo "Securing MySQL!"
            read -r -p "In another terminal, run mysql_secure_installation as root. Press [Enter] to continue..." </dev/tty
            cat > /tmp/mysqlconfig.txt <<'EOF'
Under [mysqld] add:
bind-address = 127.0.0.1
local-infile = 0
symbolic-links = 0
skip-name-resolve
require_secure_transport = ON
EOF
            echo "MySQL config guidance saved to /tmp/mysqlconfig.txt"
            read -r -p "Apply those changes to /etc/mysql/my.cnf, validate with mysqld --validate-config, then press [Enter] to continue..." </dev/tty
            chown root:root /etc/mysql/my.cnf 2>/dev/null || true
            chmod 0644 /etc/mysql/my.cnf 2>/dev/null || true
            systemctl restart mysql || true
            systemctl restart mariadb || true
            ;;
        X)
            echo "If a service is listed in the README but is not addressed here, research it manually."
            ;;
        *)
            echo "Invalid response."
            ;;
    esac
}

prohibited_pkgs() {
	pkg=$("hollywood")
	apt list --installed|grep -v '\<lib' > installed_pkgs.txt
	echo "Removing John, Hydra, Transmission, Warpinator, Netcat"
	apt purge john hydra transmission-gtk warpinator nc ncat ophcrack
	while [[ $pkg != "none" ]]; do
		read -p  "Current installed packages are in installed_pkgs.txt. If you need to uninstall something, type it in here. If you can't find a package but you know it is installed, google it." pkg
		echo "Removing $pkg!"
		apt purge $pkg
	done
}
	
unauth_files() {
    locate "*.mp3" "*.ogg" "*.wav" ".tar.*" "*.zip" "*backdoor*" "*.mov" "*.mp4" "*.php"  "*.jpg" "*.jpeg" > /home/$SUDO_USER/unauthfiles.txt
    ls /usr/games > unauthfiles.txt
    freshclam
    clamscan -r -i -l virusscan.txt &
    echo "Virus scan is currently running and will output to virus.txt."
    read -r -p "Unauthorized files have been added to unauthfiles.txt. Take a look, delete anything bad, and then press [Enter] to continue..." </dev/tty
}

pwd_pol() {
	sed -i '/^password.*pam_unix.so/a password required pam_pwhistory.so remember=5 minlen=12 ucredit=-1 ocredit=-1 dcredit=-1 lcredit=-1' /etc/pam.d/common-password
}


reboot_machine() {
	if prompt_yes_no "Would you like to reboot the machine to apply changes? 
	Warning: This script will not keep running after reboot! (y/n): "; then
		shutdown -r now
	else
		echo "Not rebooting the machine, make sure to do it at some point if you haven't already."
	fi
}

final_checks() {
    echo "Some unauthorized services may be running. Use stacer to review processes."
    echo "Review the system for any services not covered by this script."
    echo "Make sure to take a look at virus.txt to see if there are any viruses."
    echo "MAKE SURE TO TURN ON AUTOUPDATE!"
	echo "Check autorun applications for anything that runs on boot, some may also be in /etc/init.d"
}

run_it_all() {
    prerequisites
    forensics
	update
	install_packages
    root_lock
	configure_firewall
	check_and_manage_admins
	check_and_manage_users
	manage_local_users_and_groups
	adminpwd
	userpwd
	configure_pam
	pwd_pol
	configure_login_defs
	configure_ssh
	configure_web_services
	sysrq
	reperm_files
	nmap
	unauth_files
	prohibited_pkgs
	misc_sec
	final_checks
	reboot_machine
}

main2() {
	while true
	do
		clear
		show_menu
		read_options
	done

    
}


main() {
    require_root

    mkdir -p "${LOG_FILE%/*}"
    touch "${LOG_FILE}"

    echo "Success: Running with root privileges."
    echo "Security hardening script starting..."
	main2
}

show_menu(){
	
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "           ██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗         "
echo "           ██║   ██║██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██║   ██║         "
echo "           ██║   ██║██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║   ██║         "
echo "           ██║   ██║██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║   ██║         "
echo "           ╚██████╔╝██████╔╝╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝         "
echo "            ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝          "
echo "~~~~~~~~~~~~~~~~Written by: Colin Brunner~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo " "
echo "1) Forensics Questions								2) Update the machine."
echo "3) Install required pkgs.								4) Lock root account"
echo "5) Configure the firewall								6) Demote unnauthorized admins"
echo "7) Delete unauthorized users							8) Add a required user or group"
echo "9) Change all the admin passwords		 				10) All users get passwords"
echo "11) Set the lockout policy.							12) Set the password policy."
echo "13) Configure password age							14) Configure SSH."
echo "15) Configure any web services						16) Disable sysrq"
echo "17) Repermission any important files					18) Port scan the machine and send to a file"
echo "19) Find and remove any unauthorized files			20) Uninstall any unauthorized packages"
echo "21) Configure misc security settings				    22) Final checks"
echo "23) Reboot											24) RUN IT ALL"
echo "25) Secret Easter egg									26) Exit"
}

read_options(){
	
	read -p "Pease select item you wish to do: " choice

		case $choice in
			1) forensics;;
			2) update;;
			3) install_packages;;
			4) root_lock;;
			5) configure_firewall;;
			6) check_and_manage_admins;;
			7) check_and_manage_users;;
			8) manage_local_users_and_groups;;
			9) adminpwd;;
			10) userpwd;;
			11) configure_pam;;
			12) pwd_pol;;
			13) configure_login_defs;;
			14) configure_ssh;;
			15) configure_web_services;;
			16) sysrq;;
			17) reperm_files;;
			18) nmap;;
	 		19) unauth_files;;
			20) prohibited_pkgs;;
			21) misc_sec;;
			22) final_checks;;
			23) reboot_machine;;
			24) run_it_all;;
			25) easter_egg;;
			26) exit 0;;
			*) echo "Invalid Option."
			;;
		esac
	;;
	}


main "$@"
