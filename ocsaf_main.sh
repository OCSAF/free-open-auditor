#!/bin/bash

#######################################################################
################### FREE OCSAF FUNCTIONS - LIBRARY ####################
#######################################################################

#########################################################################################################################
#  FROM THE FREECYBERSECURITY.ORG TESTING-PROJECT (GNU-GPLv3) - https://freecybersecurity.org                           #
#  This script is used to perform an automated security audit and point out weaknesses.                                 #
#  To achieve this, security intelligence (OSINT) and security scanning techniques are used and                         #
#  combined with collective intelligence.                                                                               #
#                                                                                                                       #
#  Use only with legal authorization and at your own risk! ANY LIABILITY WILL BE REJECTED!                              #
#                                                                                                                       #
#  Uses BASH, DIG, HOST, GEOIPLOOKUP, SEARCHSPLOIT, SHODAN.IO, TheHarvester - https://github.com/laramies/theHarvester  #
#  Script programming by Mathias Gut, Netchange Informatik GmbH under GNU-GPLv3                                         #
#  Special thanks to the community and also for your personal project support.                                          #
#########################################################################################################################


#Integrated functions
. ocsaf_osint_sh_functions.sh
. ocsaf_scan_sh_functions.sh

#Preparing tasks
time=$(date +%d.%m.%Y-%H:%M)
echo nameserver 9.9.9.9 > /etc/resolv.conf  #Comment out if not necessary.

#User inputs
clear
echo ""
echo "####################################################################"
echo "########## Free OCSAF Security Auditor - GNU GPLv3        ##########"
echo "########## https://freecybersecurity.org                  ##########"
echo "########## MG(), Version 0.6 - Beta (17.06.18)            ##########"
echo "####################################################################"
echo ""
echo $time
unset legal
unset domain
unset full_osint
unset mailserver_osint
unset mailhavester_osint
unset mailpwned_osint
unset webserver_osint
unset shodan_osint
unset httpheader_scan

##########################################
### INPUT VALIDATION LEGAL PERMISSIONS ###
##########################################

inputvalidation_legal() {
read -p "Do you have the LEGAL PERMISSIONS to use this tool? (y=yes/n=no): " legal
}

while true
do
inputvalidation_legal
if [ "$legal" == "n" ]; then
	exit 1
elif [ "$legal" == "y" ]; then
	break	
else
	echo "Wrong input, enter y or n.."
fi
done
echo ""

##############################
## INPUT VALIDATION DOMAIN ###
##############################

inputvalidation_domain() {
read -p "Gib die Domain ein (z.B. freecybersecurity.org): " domain
}

while true
do
inputvalidation_domain
host -t ns $domain 2>&1 > /dev/null
if [ $? -eq 0 ]; then
	break
else
	echo "No valid domain.."
fi
done
echo ""

#########################################
### INPUT VALIDATION FULL OSINT ###
#########################################

inputvalidation_full_osint() {
read -p "Full OSINT with all modules (y=yes/n=no): " full_osint
}

while true
do
	inputvalidation_full_osint
	if [ "$full_osint" == "y" ] || [ "$full_osint" == "n" ]; then
		break
	else
		echo "Wrong input, enter y or n.."
	fi
done
echo ""

#########################################
### INPUT VALIDATION MAILSERVER OSINT ###
#########################################

if [ "$full_osint" == "n" ]; then
	inputvalidation_mailserver_osint() {
	read -p "Mailserver OSINT (y=yes/n=no): " mailserver_osint
	}

	while true
	do
		inputvalidation_mailserver_osint
		if [ "$mailserver_osint" == "y" ] || [ "$mailserver_osint" == "n" ]; then
			break
		else
			echo "Wrong input, enter y or n.."
		fi
	done
fi

########################################
### INPUT VALIDATION WEBSERVER OSINT ###
########################################

if [ "$full_osint" == "n" ]; then
	inputvalidation_webserver_osint() { 
	read -p "Webserver OSINT (y=yes/n=no): " webserver_osint
	}

	while true
	do
		inputvalidation_webserver_osint
		if [ "$webserver_osint" == "y" ] || [ "$webserver_osint" == "n" ]; then
			break
		else
			echo "Wrong input, enter y or n.."
		fi
	done
fi
echo ""

###########################################
### INPUT VALIDATION THEHARVESTER OSINT ###
###########################################

if [ "$full_osint" == "n" ]; then
	inputvalidation_mail_osint() {
	read -p "E-MAIL OSINT mit TheHarvester (y=yes/n=no): " mailhavester_osint
	}

	while true
	do
		inputvalidation_mail_osint
		if [ "$mailhavester_osint" == "y" ] || [ "$mailhavester_osint" == "n" ]; then
			break
		else
			echo "Wrong input, enter y or n.."
		fi
	done
fi

############################################
### INPUT VALIDATION HAVEIBEENPNED OSINT ###
############################################

if [ "$full_osint" == "n" ]; then
	if [ "$mailhavester_osint" == "y" ]; then
		inputvalidation_mailpwned_osint() {
		read -p "E-MAIL OSINT mit haveibeenpwned.com (y=yes/n=no) " mailpwned_osint
		}

		while true
		do
			inputvalidation_mailpwned_osint
			if [ "$mailpwned_osint" == "y" ] || [ "$mailpwned_osint" == "n" ]; then
				break
			else
				echo "Wrong input, enter y or n.."
			fi
		done
	fi
fi

#####################################
### INPUT VALIDATION SHODAN OSINT ###
#####################################

if [ "$full_osint" == "n" ]; then
	inputvalidation_shodan_osint() {
	read -p "Mailserver OSINT mit SHODAN.IO (y=yes/n=no): " shodan_osint
	}

	while true
	do
		inputvalidation_shodan_osint
		if [ "$shodan_osint" == "y" ] || [ "$shodan_osint" == "n" ]; then
			break
		else
			echo "Wrong input, enter y or n.."
		fi
	done
fi

##########################################
### INPUT VALIDATION HTTP-HEADER OSINT ###
##########################################

if [ "$full_osint" == "n" ]; then
	inputvalidation_httpheader_scan() {
	read -p "Webserver Header Analysis (y=yes/n=no): " httpheader_scan
	}

	while true
	do
		inputvalidation_httpheader_scan
		if [ "$httpheader_scan" == "y" ] || [ "$httpheader_scan" == "n" ]; then
			break
		else
			echo "Wrong input, enter y or n.."
		fi
	done
fi


clear
echo ""
echo "####################################################################"
echo "########## Free OCSAF Security Auditor - GNU GPLv3        ##########"
echo "########## https://freecybersecurity.org                  ##########"
echo "########## MG(), Version 0.6 - Beta (17.06.18)            ##########"
echo "####################################################################"
echo ""

#MX Records anzeigen - OSINT-Modul
if [ "$full_osint" == "y" ] || [ "$mailserver_osint" == "y" ]; then
	echo "############################"
	echo "####  MAILSERVER-CHECK  ####"
	echo "############################"
	echo ""
	mail_lookup
	echo ""
fi

#Mail Loadbalance Check - OSINT-Modul
if [ "$full_osint" == "y" ] || [ "$mailserver_osint" == "y" ]; then
	echo "##################################################################"
	echo "####  HOSTNAME MAIL-SERVER-LOADBALANCE-CHECK - VERFÜGBARKEIT  ####"
	echo "##################################################################"
	echo ""
	mail_loadbalance
	echo ""
fi

#SPF Check Funktion - OSINT-Modul
if [ "$full_osint" == "y" ] || [ "$mailserver_osint" == "y" ]; then
	echo "#####################"
	echo "####  SPF-CHECK  ####"
	echo "#####################"
	echo ""
	spf_check
	echo ""
fi

#Webserver Lookup - OSINT-Modul
if [ "$full_osint" == "y" ] || [ "$webserver_osint" == "y" ]; then
	echo "###################################"
	echo "####  WEB-SERVER-LOOKUP-CHECK  ####"
	echo "###################################"
	echo ""
	webserver_lookup
fi

#Webserver Malware Check - OSINT-Modul
if [ "$full_osint" == "y" ] || [ "$webserver_osint" == "y" ]; then
	echo "####################################"
	echo "####  WEB-SERVER-MALWARE-CHECK  ####"
	echo "####################################"
	echo ""
	malware_check
fi

#TheHarvester - OSINT-Modul
if [ "$full_osint" == "y" ] || [ "$mailhavester_osint" == "y" ]; then
	echo "#########################################"
	echo "####  MAIL Harvester - theharvester  ####"
	echo "#########################################"
	echo ""
	harvester_osint
fi

#PWNED Check - OSINT-Modul
if [ "$full_osint" == "y" ] || [ "$mailpwned_osint" == "y" ]; then
	echo "##############################################"
	echo "####  MAIL PWNED CHECK - haveeibeenpwned  ####"
	echo "##############################################"
	echo ""
	pwned_check
fi

#Shodan.io Check - OSINT-Modul
if [ "$full_osint" == "y" ] || [ "$shodan_osint" == "y" ]; then
	echo "####################################"
	echo "####  SHODAN CHECK - shodan.io  ####"
	echo "####################################"
	echo ""
	shodan_check
fi

#HTTP Header Check - Scan-Modul
if [ "$full_osint" == "y" ] || [ "$httpheader_scan" == "y" ]; then
	echo "#############################"
	echo "####  HTTP HEADER CHECK  ####"
	echo "#############################"
	echo ""
	httpheader_discovery
	httpheader_cvedetails_check
	httpheader_vuln_check
fi
