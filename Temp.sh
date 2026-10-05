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
	
	;;
	esac

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
			24) run_it_all
			25) easter_egg;;
			26) exit 0;;
			*) echo "Invalid Option."
			;;
		esac
	;;
	}

##This runs the actual script
while true
do
	clear
	show_menu
	read_options
done
