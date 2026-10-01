show_menu(){
	case "$opsys" in
	"Ubuntu")
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
				echo "1) Update the machine.			2) Set automatic updates."
				echo "3) Search for prohibited file.		4) configure the firewall."
				echo "5) Configure login screen.		6) Create any new users."
				echo "7) Change all the passwords.		8) Delete any users."
				echo "9) Set all the admins.			10) List all cronjobs."
				echo "11) Set the password policy.		12) Set the lockout policy."
				echo "13) Remove the hacking tools.		14) Configure SSH."
				echo "15) Edit the sysctl.conf.			16) Export the sudoers file."
				echo "17) List all running processes.		18) Remove NetCat."
				echo "19) Reboot the machine.			20) Secure the root account"
				echo "21) PostScript				22)Disable ctrl-alt-del"
				echo "23) Disable Virtual Terminals		24)Exit"
	
	;;
	esac

}

read_options(){
	case $opsys in
	"Ubuntu"|"Debain")
		local choice
		read -p "Pease select item you wish to do: " choice

		case $choice in
			1) update;;
			2) autoUpdate;;
			3) pFiles;;
			4) configureFirewall;;
			5) loginConf;;
			6) createUser;;
			7) chgPasswd;;
			8) delUser;;
			9) admin;;
			10) cron;;
			11) passPol;;
			12) lockoutPol;;
			13) hakTools;;
			14) sshd;;
			15) sys;;
			16) sudoers;;
			17) proc;;
			18) nc;;
	 		19) reboot;;
			20) secRoot;;
			21) cat postScript; pause;;
			22) CAD;;
			23)VirtualCon;;
			24) exit20;;
			69)runFull;;
			*) echo "Sorry that is not an option please select another one..."
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
