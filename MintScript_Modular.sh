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

install_packages() {
    log "Installing required packages..."
    apt update -y >/dev/null
    apt install -y ufw stacer pwgen libpam-pwquality clamav clamav-daemon nmap >/dev/null || warn "Packages were not installed successfully!"
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
    #awk -F: '$3 < 1000 {print "User: " $1, "UID: " $3, "Shell: " $7}' /etc/passwd > hiddenuser.txt
    echo "Any user with an ID of less than 1000 is hidden, make sure you check for those!"
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
    for i in admins.txt; do
        if [[i != $SUDOUSER ]]; then
            echo "$i:$(pwgen -sy 20 1)" | chpasswd
        fi
    done

    }

userpwd() {
    for i in users.txt; do
        if [[i != $SUDOUSER ]]; then
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

unauth_files() {
    locate "*.mp3" "*.ogg" "*.wav" ".tar.*" "*.zip" "*backdoor*" "*.mov" "*.mp4" "*.php"  "*.jpg" "*.jpeg" > /home/$SUDO_USER/unauthfiles.txt
    ls /usr/games > unauthfiles.txt
    freshclam
    clamscan -r -i / & > virus.txt
    echo "Virus scan is currently running and will output to virus.txt."
    read -r -p "Unauthorized files have been added to unauthfiles.txt. Take a look, delete anything bad, and then press [Enter] to continue..." </dev/tty
}

final_checks() {
    echo "Some unauthorized services may be running. Use stacer to review processes."
    echo "Review the system for any services not covered by this script."
    echo "Make sure to take a look at virus.txt to see if there are any viruses."
    echo "MAKE SURE TO TURN ON AUTOUPDATE!"
}

main() {
    require_root

    mkdir -p "${LOG_FILE%/*}"
    touch "${LOG_FILE}"

    echo "Success: Running with root privileges."
    echo "Security hardening script starting..."

    if prompt_yes_no "Have the forensics questions been answered or are they answerable?"; then
        echo "Proceeding..."
    else
        echo "Please answer them first."
        exit 1
    fi

    if prompt_yes_no "Does the README specify not to update packages?"; then
        echo "Update manually as required by the README."
    else
        echo "Proceeding with package updates..."
        apt update -y >/dev/null
        apt list --upgradable > "${HOME_DIR}/upgraded_pkgs.txt" 2>/dev/null || true
        apt upgrade -y >/dev/null || warn "Package upgrade returned a non-zero exit code."
        echo "Check for packages installed via Mint Store and uninstall anything that is not approved."
    fi

    install_packages
    configure_firewall
    root_lock

    configure_pam
    check_and_manage_admins
    check_and_manage_users
    manage_local_users_and_groups
    configure_login_defs
    configure_ssh
    configure_web_services
    final_checks

    echo "Hardening script complete. Review all changes manually before deployment."
}

main "$@"
