show_menu(){
	
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "           ██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗         "
echo "           ██║   ██║██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██║   ██║         "
echo "           ██║   ██║██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║   ██║         "
echo "           ██║   ██║██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║   ██║         "
echo "           ╚██████╔╝██████╔╝╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝         "
echo "            ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝          "
echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo " "
echo "1) Update the machine.			2) Install required packages."
echo "3) Lock the root account.			4) Configure the firewall."
echo "5) Demote unathorized admins		6) Delete unauthorized users."
echo "7) Add users/groups				8) Change all the admin passwords.."
echo "9) N/a			 				10) All users get passwords"
echo "11) Set the password policy.		12) Set the lockout policy."
echo "13) Configure password age		14) Configure SSH."
echo "15) Configure any web services	16) Repermission important files"
echo "17) Port scan	to a file			18) Find and remove prohibited files"
echo "19) Reboot the machine.			20)Uninstall all unauthorized packages"
echo "21) Final checks				    22)Disable sysrq"
echo "23) Misc machine security configs		24)Exit"
echo "25) Forensics Questions Help		26) RUN EVERYTHING!"
	
	;;
	esac

}

read_options(){
	
	read -p "Pease select item you wish to do: " choice

		case $choice in
			1) update;;
			2) install_packages;;
			3) rootlock;;
			4) configure_firewall;;
			5) check_and_manage_admins;;
			6) check_and_manage_users;;
			7) manage_local_users_and_groups;;
			8) adminpwd;;
			9) userpwd;;
			10) configure_pam;;
			11) passPol;;
			12) lockoutPol;;
			13) hakTools;;
			14) configure_ssh;;
			15) configure_web_services;;
			16) reperm_files;;
			17) nmap;;
			18) prohibited_files;;
	 		19) reboot;;
			20) prohibited_pkgs;;
			21) final_checks;;
			22) sysrq;;
			23) misc_configs;;
			24) exit 1
			25) forensics;;
			26)runFull;;
			*) echo "Invalid Option."
			;;
		esac
	;;
	}

##This runs .the actual script
while true
do
	clear
	show_menu
	read_options
done
