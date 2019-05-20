#!/bin/bash

###############################################################################
################### FREE OCSAF AUDITOR MAIN - 0.6.3 (BETA) ####################
###############################################################################

#########################################################################################################################
#  FROM THE FREECYBERSECURITY.ORG TESTING-PROJECT (GNU-GPLv3) - https://freecybersecurity.org                           #
#  This script is used to perform an automated security audit and point out weaknesses.                                 #
#  To achieve this, security intelligence (OSINT) and security scanning techniques are used and                         #
#  combined with collective intelligence.                                                                               #
#                                                                                                                       #
#  Use only with legal authorization and at your own risk! ANY LIABILITY WILL BE REJECTED!                              #
#                                                                                                                       #
#  Uses BASH, DIG, HOST, GEOIPLOOKUP, SEARCHSPLOIT, SHODAN.IO, TheHarvester - https://github.com/laramies/theHarvester  #
#  Script programming by Mathias Gut MG(), Netchange Informatik GmbH under GNU-GPLv3                                    #
#  Special thanks to the community and also for your personal project support.                                          #
#########################################################################################################################


#######################
### Preparing tasks ###
#######################

time=$(date +%d.%m.%Y-%H:%M)
echo nameserver 9.9.9.9 > /etc/resolv.conf  #Comment out if not necessary. With Security look https://www.quad9.net.
#echo nameserver 9.9.9.10 > /etc/resolv.conf  #Comment out if not necessary. No Security look https://www.quad9.net.

#Check if vulnreport folder exists and create otherwise
if ! [ -d "./inputs/temp" ]; then
	mkdir ./inputs/temp
fi

#Check if the required programs are installed
program=(python3 dig host jq geoiplookup)
for i in "${program[@]}"; do
	if [ -z $(command -v ${i}) ]; then
		echo "${i} is not installed."
		exit
	fi
done
unset program


############################
### Integrated functions ###
############################

. libraries/bash/ocsaf_osint_sh_functions.sh        #All OSINT functions
. libraries/bash/ocsaf_scan_sh_functions.sh         #All SCAN function


#####################################
### SCRIPT USAGE - OTIONS - HELP  ###
#####################################

#script usage
usage() {
	echo "Free OCSAF Security Auditor BETA 0.6.3 - GPLv3 (https://freecybersecurity.org)"
	echo "Use only with legal authorization and at your own risk!"
       	echo "ANY LIABILITY WILL BE REJECTED!"
       	echo ""	
	echo "USAGE:" 
	echo "  ./freeauditor.sh -d <domain> [Options]" 
       	echo ""	
	echo "EXAMPLE:"
       	echo "  ./freeauditor.sh -d freecybersecurity.org -w"
       	echo "  ./freeauditor.sh -d freecybersecurity.org -mwi"
       	echo ""	
	echo "OPTIONS:"
	echo "  -h, help - this beautiful text"
	echo "  -d <DOMAIN>"
	echo "  -a, aggressiv, any modules (unsafe)"
	echo "  -c, colors off for better readability in files"
	echo "  -o, any osint modules"
	echo "  -w, webserver analysis"
	echo "  -i, httpheader analysis"
	echo "  -m, mailserver analysis"
	echo "  -s, shodan api (not yet implemented)"
	echo "  -t, theharvester script"
	echo "  -p, haveibeenpwned api (needs -t option)"
	echo "  -z, zero - delete temp-files"
       	echo ""
	echo "COLLECTIVE INTELLIGENCE:"
	echo "  CI-files can be found in ./inputs/project/:"
	echo "  -SPF-analysis = ./inputs/project/spf/"
	echo "  -Blacklist-analysis = ./inputs/project/bl/"
	echo "  -HTTP-header-analysis = ./inputs/project/http/"
	echo ""	
	echo "OTHER FILES:"
	echo "  -TEMP-files = ./inputs/temp/ (..http-header files)"	
	echo ""	
	echo "NOTES:"
	echo "#See also the MAN PAGE - https://freecybersecurity.org"
}

###############################
### GETOPTS - TOOL OPTIONS  ###
###############################

while getopts ":d:achowimstpiz" opt; do
	case ${opt} in
		h) usage; exit 1;;
		a) any_modules=1; opt_check=1;;
		c) colors=1;;
		d) domain="$OPTARG"; opt_domain=1;
			if [[ "$domain" = -* ]]; then
				echo "**No domain argument set**"
				echo ""
				usage
				exit 1
			else
				host -t ns $domain 2>&1 > /dev/null
				if [ $? -eq 0 ]; then
					domain="$OPTARG"
				else
					echo "**$domain is not a valid domain**"
					echo ""
					usage
					exit 1
				fi
			fi
   		;;
		o) any_osint=1; opt_check=1;;
		w) webserver_osint=1; opt_check=1;;
		i) httpheader_osint=1; opt_check=1;;
		m) mailserver_osint=1; opt_check=1;;
		s) shodan_osint=1; opt_check=1;;
		t) theharvester_osint=1; opt_check=1;;
		p) pwned_osint=1; opt_check=1;;
		z) zero_del=1; opt_check=1;;
		\?) echo "**Unknown option: -$OPTARG **" >&2; echo ""; usage; exit 1;;
        	:) echo "**Missing option argument for -$OPTARG **" >&2; echo ""; usage; exit 1;;
		*) usage; exit 1;;
  	esac
  	done
	shift $(( OPTIND - 1 ))

#Check if domain set and not zero_del option set
if [ "$opt_domain" == "" ] && [ "$zero_del" == "" ]; then
	echo "**No domain set**"
	echo ""
	usage
	exit 1
fi

#Check if a option is set
if [ "$opt_check" == "" ]; then
	echo "**No option set**"
	echo ""
	usage
	exit 1
fi


##############
### COLORS ###
##############

. libraries/bash/colors.sh                          #All COLOR codes


####################
### MAIN PROGRAM ###
####################

clear
echo ""
echo "####################################################################"
echo "########## Free OCSAF Security Auditor - GNU GPLv3        ##########"
echo "########## https://freecybersecurity.org                  ##########"
echo "########## MG(), Version 0.6.3 - Beta (06.05.19)          ##########"
echo "####################################################################"
echo ""
echo $time

#Zero - delete all temp files
if [ "$zero_del" == "1" ]; then
	touch ./inputs/temp/delete_$time
	rm ./inputs/temp/*
	echo "##############################"
	echo "####  TEMP FILES DELETED  ####"
	echo "##############################"
	echo ""
fi

#MX Records anzeigen - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$mailserver_osint" == "1" ]; then
	echo "############################"
	echo "####  MAILSERVER-CHECK  ####"
	echo "############################"
	echo ""
	mail_lookup
	echo ""
fi

#Mail Loadbalance Check - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$mailserver_osint" == "1" ]; then
	echo "##################################################"
	echo "####  HOSTNAME MAIL-SERVER-LOADBALANCE-CHECK  ####"
	echo "##################################################"
	echo ""
	mail_loadbalance
	echo ""
fi

#SPF Check Funktion - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$mailserver_osint" == "1" ]; then
	echo "#####################"
	echo "####  SPF-CHECK  ####"
	echo "#####################"
	echo ""
	spf_check
	echo ""
fi

#DMARC Check Funktion - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$mailserver_osint" == "1" ]; then
	echo "#######################"
	echo "####  DMARC-CHECK  ####"
	echo "#######################"
	echo ""
	funcDMARCcheck
	echo ""
fi

#Webserver Lookup - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$webserver_osint" == "1" ]; then
	echo "###################################"
	echo "####  WEB-SERVER-LOOKUP-CHECK  ####"
	echo "###################################"
	echo ""
	webserver_lookup
fi

#Webserver Malware Check - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$webserver_osint" == "1" ]; then
	echo "####################################"
	echo "####  WEB-SERVER-MALWARE-CHECK  ####"
	echo "####################################"
	echo ""
	malware_check
fi

#Webserver CAA Check - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$webserver_osint" == "1" ]; then
	echo "#######################################"
	echo "####  WEB-SERVER-CAA-RECORD-CHECK  ####"
	echo "#######################################"
	echo ""
	funcCAAcheck
fi

#Webserver DNSSEC Check - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$webserver_osint" == "1" ]; then
	echo "##########################################"
	echo "####  WEB-SERVER-DNSSEC-RECORD-CHECK  ####"
	echo "##########################################"
	echo ""
	funcDNSSECcheck
fi

#TheHarvester - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$theharvester_osint" == "1" ]; then
	echo "#########################################"
	echo "####  MAIL Harvester - theharvester  ####"
	echo "#########################################"
	echo ""
	harvester_osint
fi

#PWNED Check - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$pwned_osint" == "1" ]; then
	echo "##############################################"
	echo "####  MAIL PWNED CHECK - haveeibeenpwned  ####"
	echo "##############################################"
	echo ""
	pwned_check
fi

#Shodan.io Check - OSINT-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$shodan_osint" == "1" ]; then
	echo "####################################"
	echo "####  SHODAN CHECK - shodan.io  ####"
	echo "####################################"
	echo ""
	shodan_check
fi

#HTTP Header Check - Scan-Modul
if [ "$any_modules" == "1" ] || [ "$any_osint" == "1" ] || [ "$httpheader_osint" == "1" ]; then
	echo "#############################"
	echo "####  HTTP HEADER CHECK  ####"
	echo "#############################"
	echo ""
	httpheader_discovery
	funcSecurityheaderCheck
	httpheader_cvedetails_check
	httpheader_vuln_check
fi

###################### END ######################