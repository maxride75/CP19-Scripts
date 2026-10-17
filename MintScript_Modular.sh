#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="${0##*/}"
readonly LOG_FILE="/var/log/${SCRIPT_NAME%.sh}.log"

TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
HOME_DIR="/home/${TARGET_USER}"
RUN_ALL=0

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
	log "Success! Root achieved! Running the hardening script!"
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

prerequisites() {
	echo "----------------------PREREQUISITES-------------------------"
	echo "This script will fail if these are not done correctly!!"
	echo "This part is step-by-step, and please press [Enter] after each step is done."
	read -r -p "1. Launch Update Manager and make sure apt repos are set up correctly, e.g. they can connect!"
	read -r -p "2. Create a text file called admins.txt and place the list of admins from the README in there. DO NOT INCLUDE PASSWORDS!"
	read -r -p "3. Create a text file called users.txt and place the list of users from the README in there. AGAIN, DO NOT INCLUDE PASSWORDS!"
	read -r -p "4. If the README specifies to create a new user, make a new directory in your home folder called user, and place a file called user.txt with the new user you need to create in it."
	read -r -p "5. Likewise, if the README specifies to create a new group, make a new directory in your home folder called group, but this time, create 2 text files, named
	user.txt, and group.txt. Place the name of the group you want to create in group.txt, and the users who should be in the group in user.txt."
	read -r -p "If you finished all of those, great! Press [Enter] to continue! "
	
}
	

forensics() {
	if prompt_yes_no "Have the forensics questions been answered or are they answerable?"; then
		echo "Nice job!"
	else
        cd "${HOME_DIR}"
		log "Forensics help is in ${HOME_DIR}/forensics.txt, but help can also be found by googling..."
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
		echo "Sometimes Wireshark may be installed as part of a question. If the question asks for an IP, process of elimination usually helps, e.g. enter one IP, save the file,
		and if you don't get points, try the other IP from the pcap file." >> forensics.txt
		echo "Take a look at it if you need help!"
    fi
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

update() {
    if prompt_yes_no "Does the README specify not to update packages?"; then
        echo "Update manually as required by the README."
    else
        log "Proceeding with package updates..."
        apt-get update -y >/dev/null || warn "Package update returned a non-zero exit code."
        apt list --upgradable > "${HOME_DIR}/upgraded_pkgs.txt" 2>/dev/null || true
        apt-get upgrade -y >/dev/null || warn "Package upgrade returned a non-zero exit code."
        log "Check for packages installed via Mint Store and uninstall anything that is not approved."
    fi
    if [[ ${run_all} != 1 ]]; then
		menu
	fi
}
install_packages() {
	log "Installing required packages..."
    apt-get update -y >/dev/null
    apt-get install -y ufw stacer pwgen libpam-pwquality clamav clamav-daemon rkhunter unix-privesc-check gedit >/dev/null || warn "Packages were not installed successfully!"
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

configure_firewall() {
	log "Enabling UFW firewall..."
    ufw --force enable >/dev/null || warn "UFW enable command returned non-zero; check status manually."
	log "Firewall has been enabled!"
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
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

    log "PAM modules have been created. Please enable them with pam-auth-update."
    read -r -p "Press [Enter] to continue once pam-auth-update is done..." </dev/tty
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
	
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
        echo "These are the potentially bad admins:"
        cat "${HOME_DIR}/maybebadadmins.txt"
        if prompt_yes_no "Would you like to demote the suspect admins?"; then
            while IFS= read -r admin; do
                [[ -z "${admin}" ]] && continue
                log "Demoting user: ${admin}"
                deluser "${admin}" sudo adm || warn "Failed to demote ${admin}"
            done < "${HOME_DIR}/maybebadadmins.txt"
			echo "If a user was demoted, and shouldn't have been, check the log and promote them!"
        else
            log "Make sure to demote them for points!"
        fi
    else
        log "No suspect admins found, but this doesn't mean they aren't there! Manually check for them!"
    fi
	if [[ ${run_all} != 1 ]]; then
		menu
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
                log "Removing user: ${user}"
                userdel -r "${user}" || warn "Failed to remove ${user}"
            done < "${HOME_DIR}/maybebadusers.txt"
			echo "If a user was demoted, and shouldn't have been, check the log and promote them!"
        else
            echo "Make sure to delete them for points!"
        fi

    else
        log "No suspect admins found, but this doesn't mean they aren't there! Manually check for them, after the script is done!"
    fi
	
	awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -v root > uid0.txt
	if [[ -f "uid0.txt" ]]; then
		log "USER WITH ROOT PERMS FOUND!!! DEMOTE IMMEDIATELY!!!"
		cat uid0.txt
		if prompt_yes_no "Would you like to change their UID (y/n): "; then
			BADUSER=$(cat uid0.txt)
			killall -u "$BADUSER"
			usermod -u 3024 "$BADUSER"
			groupmod -g 3024 "$BADUSER"
		fi
	fi
	
	
	awk -F: '$3 < 1000 {print "User: " $1, "UID: " $3, "Shell: " $7}' /etc/passwd > "${HOME_DIR}"/hiddenuser.txt
	if [[ -f "hiddenuser.txt" ]]; then
		echo "These users have a UID that is less than 1000, meaning they are hidden"
    	cat hiddenuser.txt
    	echo "Make sure they are authorized, because the script does not automatically remove hidden users!"
	fi
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

manage_local_users_and_groups() {
    log "Additional user/group management..."

    while true; do
        local choice
        choice="$(prompt_choice "Does the README require extra user management? N for none... (G/U/N): " "G U N")"

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
                log "Making group ${group_name}"
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
                log "Making user ${user_name}"
                useradd -m -s /bin/bash "${user_name}" || warn "User ${user_name} may already exist."
                log "User ${user_name} made."
                passwd -E "${user_name}"
				log "User ${user_name}'s password is set to expire when they login."
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
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}
adminpwd() {
    if [[ ! -f "${HOME_DIR}/admins.txt" ]]; then
        warn "${HOME_DIR}/admins.txt not found. Create it with the approved admin list before continuing."
        return 0
    fi
	log "Changing all admin passwords, except yours!"
	while IFS= read -r user; do
        [[ -z "${user}" ]] && continue
        if [[ "$user" != "$TARGET_USER" ]]; then
            echo "$user:$(pwgen -sy 20 1)" | chpasswd
        fi
    done < admins.txt
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

userpwd() {
    if [[ ! -f "${HOME_DIR}/users.txt" ]]; then
        warn "${HOME_DIR}/users.txt not found. Create it with the approved user list before continuing."
        return 0
    fi
	log "Changing user passwords! If a user doesn't have one, it has been added for them!"
	while IFS= read -r user; do
        [[ -z "${user}" ]] && continue
        if [[ "$user" != "$TARGET_USER" ]]; then
            echo "$user:$(pwgen -sy 20 1)" | chpasswd
        fi
    done < users.txt
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}
configure_login_defs() {
    log "Configuring login.defs password policy..."
    local config_doc="/etc/login.defs"

    set_config_value "${config_doc}" "PASS_MAX_DAYS" "60"
    set_config_value "${config_doc}" "PASS_MIN_DAYS" "20"
    set_config_value "${config_doc}" "PASS_WARN_AGE" "7"
    log "/etc/login.defs updated successfully."
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

misc_sec() {
    echo "Restricting users from dmesg!"
	echo "kernel.dmesg_restrict=1" | tee -a /etc/sysctl.d/6-dmesg-sudo.conf >/dev/null

	log "Changing all users and admins' password ages to 60 days!"
    while IFS= read -r user; do
        [[ -z "${user}" ]] && continue
        if [[ "${user}" != "${TARGET_USER}" ]]; then
            chage -M 60 "${user}" || warn "Failed to set password max age for ${user}"
        fi
    done < <(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)

    log "All unhidden users' maximum password age (not yours) was set to 60 days."
    read -r -p "Check for hidden users now and adjust them manually if needed. Press [Enter] to continue..." </dev/tty
    log "Changing sysctl parameters!"
	
	set_config_value "/etc/sysctl.conf" "net.ipv4.tcp_syncookies =" "1"
    set_config_value "/etc/sysctl.conf" "net.ipv4.conf/all.rp_filter =" "1"
	set_config_value "/etc/sysctl.conf" "net.ipv4.conf.default.rp_filter =" "1"
	set_config_value "/etc/sysctl.conf" "net.ipv4.conf.all.accept_source_route =" "0"
	set_config_value "/etc/sysctl.conf" "net.ipv4.conf.default.accept_source_route =" "0"
	set_config_value "/etc/sysctl.conf" "net.ipv4.conf.all.accept_redirects =" "0"
	set_config_value "/etc/sysctl.conf" "net.ipv4.conf.default.accept_redirects =" "0"
	set_config_value "/etc/sysctl.conf" "net.ipv4.conf.all.send_redirects =" "0"
	set_config_value "/etc/sysctl.conf" "net.ipv4.conf.all.log_martians =" "1"
	set_config_value "/etc/sysctl.conf" "net.ipv4.icmp_echo_ignore_broadcasts =" "1"
	set_config_value "/etc/sysctl.conf" "net.ipv4.icmp_ignore_bogus_error_responses =" "1"
	set_config_value "/etc/sysctl.conf" "net.ipv4.ip_forward =" "0"
	set_config_value "/etc/sysctl.conf" "net.ipv4.tcp_rfc1337 =" "1"
	set_config_value "/etc/sysctl.conf" "kernel.randomize_va_space =" "2"
	set_config_value "/etc/sysctl.conf" "fs.suid_dumpable =" "0"
	set_config_value "/etc/sysctl.conf" "fs.protected_hardlinks =" "1"
	set_config_value "/etc/sysctl.conf" "fs.protected_symlinks =" "1"

	sysctl --system >/dev/null || warn "sysctl --system returned a non-zero exit status."
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

configure_ssh() {
    log "Checking SSH settings..."
    if ! prompt_yes_no "Does the README say users need to log in via SSH?"; then
		if prompt_yes_no "Would you like to attempt to uninstall SSH?"; then
        apt-get purge openssh-server
        return 0
		else
			log "Stopping and disabling sshd!"
			systemctl stop ssh || warn "Stopping sshd returned a non-zero error code!" 
			systemctl disable ssh  || warn "Disabling sshd returned a non-zero error code!"
			return 0
		fi
    fi

    log "Securing SSH!"
    local ssh_config="/etc/ssh/sshd_config"
    if [[ ! -f "${ssh_config}" ]]; then
        warn "No sshd_config file found. Skipping SSH hardening."
        return 0
    fi
    set_config_value "${ssh_config}" "PermitRootLogin" "no"
    set_config_value "${ssh_config}" "UsePAM" "yes"
    set_config_value "${ssh_config}" "PermitEmptyPasswords" "no"
    set_config_value "${ssh_config}" "DisableForwarding" "yes"
    set_config_value "${ssh_config}" "X11Forwarding" "no"
	set_config_value "${ssh_config}" "MaxAuthTries" "6"
	set_config_value "${ssh_config}" "PermitTunnel" "no"
	set_config_value "${ssh_config}" "GatewayPorts" "no"
	set_config_value "${ssh_config}" "MaxAuthTries" "6"
	log "SSH has been secured, reloading SSH now..."
    systemctl reload ssh || warn "Failed to reload SSH service."
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

root_lock() {
    log "Locking the root account!"
	passwd -l root || warn "Failed to lock root account."
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
	
}
sysrq() {
	echo "Disabling sysrq!"
	set_config_value "/etc/sysctl.conf" "kernel.sysrq =" "0"
	sysctl --system || warn "sysctl --system returned a non-zero exit status."
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
	
}
reperm_files() {
    log "Making sure critical files are permissioned correctly!"
	cd /etc
    chown root:root sudoers shadow passwd ssh/sshd_config /boot/grub/grub.cfg
    chmod 440 sudoers
    chmod 600 shadow /boot/grub/grub.cfg ssh/sshd_config 
    chmod 644 passwd
    cd "${HOME_DIR}"
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
	
}

easter_egg() {
   apt-get install xterm -y > /dev/null
   xterm -hold -e 'curl ascii.live/rick' &
   if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

nmap_machine() {
	apt-get install nmap -y
	log "Scanning ports!"
	nmap -sT -o "${HOME_DIR}"/nmap.txt localhost
	echo "This machine's ports have been scanned, ouput is in ${HOME_DIR}/nmap.txt"
	echo "Take a look, more information can be found at speedguide.net or via ss -tlnp."
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}
configure_web_services() {
    local choice
    choice="$(prompt_choice "Is the computer running a web or fileshare service that has been specified in the README? (nginX/Apache/FTP/Mysql/Php/N)): " "X A F M N P")"

    case "${choice}" in
        X)
            log "Securing nginx!"
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
            log "The nginx configuration instructions have been saved to /tmp/nginxconfig.txt"
            read -r -p "Add the lines manually to /etc/nginx/nginx.conf, then press [Enter] to continue..." </dev/tty
            nginx -t || warn "nginx config test failed; check the configuration manually."
            systemctl reload nginx || warn "Failed to reload nginx."
            ;;
        A)
            log "Securing Apache!"
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
			else
				warn "Apache base configuration file not found. Skipping Apache hardening."
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
            log "The FTP configuration lines have been saved to /tmp/ftpconfig.txt"
            read -r -p "Add the FTP config to /etc/vsftpd.conf, then press [Enter] to continue..." </dev/tty
            systemctl restart vsftpd || warn "vsftpd restart failed."
            ;;
        M)
            log "Securing MySQL!"
            read -r -p "In another terminal, run mysql_secure_installation as root. After, press [Enter] to continue..." </dev/tty
            cat > /tmp/mysqlconfig.txt <<'EOF'
Under [mysqld] add:
bind-address = 127.0.0.1
local-infile = 0
symbolic-links = 0
skip-name-resolve
require_secure_transport = ON
EOF
            log "MySQL config guidance saved to /tmp/mysqlconfig.txt"
            read -r -p "Apply those changes to /etc/mysql/my.cnf, validate with mysqld --validate-config, then press [Enter] to continue..." </dev/tty
            chown root:root /etc/mysql/my.cnf 2>/dev/null || true
            chmod 0644 /etc/mysql/my.cnf 2>/dev/null || true
            systemctl restart mysql || true
            systemctl restart mariadb || true
            ;;
        N)
            log "If a service is listed in the README but is not addressed here, research it manually."
			log "If the computer is running a service not specified in the README, use systemctl stop pkg"
            ;;
		P)
			log "PHP security depends on what process it runs under. To secure it, googling is necessary."
			log "To identify what process it runs under, look for these!"
			log "Normally the PHP process will look like php-form or php-fpmX.X" 
			log "But, if Apache is running, PHP will not be in the process list, because it runs under the apache2 process."
			log "Also, if the computer is running Nginx, PHP's name will be php-fpm."
			log "To find these, use ps aux|grep php/apache2/httpd to find it!"
			;;
			
        *)
            echo "Invalid response."
            ;;
    esac
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

prohibited_pkgs() {
	local pkg="hollywood"
	apt list --installed|grep -v '\<lib' > installed_pkgs.txt
	log "Removing bad packages!"
	apt-get purge john hydra transmission-gtk warpinator ophcrack doona xprobe squid 
	apt-get autoremove
	log "Definitely bad packages have been removed, but other packages like Samba, Nginx, and FTP have not been removed."
	log "If you want to remove other software, the Mint Store is a good place to start!"
	while [[ $pkg != "none" ]]; do
		echo "Installed packages are in installed_pkgs.txt. THIS FILE DOESN'T UPDATE!"
		echo "If you can't find a package but you know it is installed, google it."
		echo "Note: Please don't uninstall netcat if you are planning to use nmap because nmap requires netcat to function."
		read -r -p  "If you need to uninstall something, type it in here. If you don't need to uninstall something, type none. " pkg
		echo "Removing $pkg!"
		apt-get purge "$pkg"
	done
	if prompt_yes_no "Would you like to uninstalll uneeded dependencies?"; then
        apt-get autoremove
	fi
	apt-get autoclean
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}
	
unauth_files() {
    log "Finding bad files!"
	locate "*.mp3" "*.ogg" "*.wav" ".tar.*" "*.zip" "*backdoor*" "*.mov" "*.mp4" "*.php"  "*.jpg" "*.jpeg" > "${HOME_DIR}"/unauthfiles.txt
    ls /usr/games > unauthfiles.txt
    log "Unauthorized files have been added to unauthfiles.txt."
	read -r -p "Take a look, delete anything bad, and then press [Enter] to continue..." </dev/tty
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

pwd_pol() {
	log "Adding a password complexity policy!"
	sed -i '/^password.*pam_unix.so/a password required pam_pwhistory.so remember=5 minlen=12 ucredit=-1 ocredit=-1 dcredit=-1 lcredit=-1' /etc/pam.d/common-password
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

virus() {
	log "Scanning for viruses!"
	freshclam
    clamscan -r -i -l virusscan.txt &
    log "Virus scan is currently running and will output to virus.txt."
	log "Updating the rootkit hunter."
	rkhunter --update
	log "Hunting for rootkits and other various malware!"
	rkhunter -c 
	log "Checking for common privelege escalation vectors!"
	unix-privesc-check standard
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

reboot_machine() {
	if prompt_yes_no "Would you like to reboot the machine to apply changes? 
	Warning: This script will not keep running after reboot! (y/n): "; then
		shutdown -r now
	else
		echo "Not rebooting the machine, make sure to do it at some point if you haven't already."
	fi
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}

final_checks() {
    log "Some unauthorized services may be running. Use stacer to review processes."
    log "Review the system for any services not covered by this script."
    log "Make sure to take a look at virusscan.txt to see if there are any viruses."
    log "MAKE SURE TO TURN ON AUTOUPDATE!"
	log "Check autorun applications for anything that runs on boot, some may also be in /etc/init.d"
	echo "Make sure to check the log in ${LOG_FILE} to see if there were any errors!"
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
	
}
cleanup() {
	log "Cleaning up!"
	rm -f /tmp/ftpconfig.txt /tmp/mysqlconfig.txt /tmp/nginxconfig.txt
	log "Removing unneeded software and dependencies installed by the script!"
	apt-get remove byobu nmap unix-privesc-check rkhunter stacer pwgen -y > /dev/null
	apt-get autoremove -y > /dev/null
	apt-get autoclean
	if [[ ${run_all} != 1 ]]; then
		menu
	fi
}
kitchen_sink() {
    $RUN_ALL=1
	forensics
	read -r -p "Next up is updating the computer! Press [Enter] to continue... "
	update
	read -r -p "Next up is installing required packages! Press [Enter] to continue... "
	install_packages
	read -r -p "Next up is locking the root account! Press [Enter] to continue... "
    root_lock
	read -r -p "Next up is configuring the firewall! Press [Enter] to continue... "
	configure_firewall
	read -r -p "Next up is managing admins! Press [Enter] to continue... "
	check_and_manage_admins
	read -r -p "Next up is managing users! Press [Enter] to continue... "
	check_and_manage_users
	read -r -p "Next up is creating users and groups! Press [Enter] to continue... "
	manage_local_users_and_groups
	read -r -p "Next up is changing insecure admin passwords! Press [Enter] to continue... "
	adminpwd
	read -r -p "Next up is changing insecure user passwords! Press [Enter] to continue... "
	userpwd
	read -r -p "Next up is adding an account lockout policy! Press [Enter] to continue... "
	configure_pam
	read -r -p "Next up is making a password policy! Press [Enter] to continue... "
	pwd_pol
	read -r -p "Next up is configuring password ages! Press [Enter] to continue... "
	configure_login_defs
	read -r -p "Next up is securing SSH! Press [Enter] to continue... "
	configure_ssh
	read -r -p "Next up is securing web and fileshare services! Press [Enter] to continue... "
	configure_web_services
	read -r -p "Next up is disabling SYSRQ! Press [Enter] to continue... "
	sysrq
	read -r -p "Next up is repermissioning files! Press [Enter] to continue... "
	reperm_files
	read -r -p "Next up is scanning the machine for open ports! Press [Enter] to continue... "
	nmap_machine
	read -r -p "Next up is finding unauthorized files! Press [Enter] to continue... "
	unauth_files
	read -r -p "Next up is uninstalling bad packages! Press [Enter] to continue... "
	prohibited_pkgs
	read -r -p "Next up is making misc security configurations! Press [Enter] to continue... "
	misc_sec
	read -r -p "Next up is scanning for viruses! Press [Enter] to continue... "
	virus
	read -r -p "Next up is final checks! Press [Enter] to continue... "
	final_checks
	read -r -p "Next up is cleaning up! Press [Enter to continue... "
	cleanup
	read -r -p "And last up is rebooting the machine! Press [Enter] to continue... "
	reboot_machine
}

exit_script(){
	clear
	echo "See you soon!"
	fastfetch --structure logo --logo kali
	echo "Script written by Colin and the rest of BWHS-3 CP19 team"
	exit 0
}

inet_check(){
	if ping -c 4 8.8.8.8 &> /dev/null; then
    	log "You are connected to the internet!"
	else
  	 	err "You are not connected to the internet! This script won't work!"
	fi
}

show_menu(){
echo "~~~~~~~~~~~~~~~~~~~~~MINT HARDENING SCRIPT~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
fastfetch --structure logo --logo linuxmint
echo "~~~~~~~~~~~~~~~~Written by: Colin and the rest of BWHS-3 CP19 team~~~~~~~~"
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
echo "21) Configure security settings				    	22) Virus scan"
echo "23) Cleanup											24) Final checks"
echo "25) Reboot											26) Full Machine Harden"
echo "27) Secret Easter Egg									28) Exit"
}

read_options(){
	
	read -r -p "What would you like to do? " choice

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
		18) nmap_machine;;
	 	19) unauth_files;;
		20) prohibited_pkgs;;
		21) misc_sec;;
		22) virus;;
		23) cleanup;;
		24) final_checks;;
		25) reboot_machine;;
		26) kitchen_sink;;
		27) easter_egg;;
		28) exit_script;;
		*) echo "Invalid Option."
		;;
	esac
	}


menu() {
	clear
	show_menu
	read_options
}


main() {
    require_root
	#inet_check
	apt-get install fastfetch -y > /dev/null &
	prerequisites
	
    mkdir -p "${LOG_FILE%/*}"
    touch "${LOG_FILE}"
	menu
	
}

main "$@"
