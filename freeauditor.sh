#!/bin/bash

###############################################################################
################### FREE OCSAF AUDITOR MAIN - 0.6.5 (BETA) ####################
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
program=(python3 dig host jq geoiplookup theHarvester)
for i in "${program[@]}"; do
	if [ -z $(command -v ${i}) ]; then
		echo "${i} is not installed."
		count=1
	fi
done
	if [[ $count -eq 1 ]]; then
		exit
	fi

unset program
unset count


############################
### Integrated functions ###
############################

. libraries/bash/ocsaf_osint_sh_functions.sh        #All OSINT functions
. libraries/bash/ocsaf_scan_sh_functions.sh         #All SCAN function


#####################################
### SCRIPT USAGE - OTIONS - HELP  ###
#####################################

#script funcHelp
funcHelp() {
	echo "Free OCSAF Security Auditor BETA 0.6.5 - GPLv3 (https://freecybersecurity.org)"
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
	echo "  -t, theHarvester script (mail- and dns-recon)"
	echo "  -p, haveibeenpwned api (needs api-key and -t option)"
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
		h) funcHelp; exit 1;;
		a) _ANY_MODULES=1; _OPT_CHECK=1;;
		c) _COLORS=1;;
		d) _DOMAIN="$OPTARG"; _OPT_DOMAIN=1;
			if [[ "${_DOMAIN}" = -* ]]; then
				echo "**No domain argument set**"
				echo ""
				funcHelp
				exit 1
			else
				host -t ns ${_DOMAIN} 2>&1 > /dev/null
				if [ $? -eq 0 ]; then
					_DOMAIN="$OPTARG"
				else
					echo "**${_DOMAIN} is not a valid domain**"
					echo ""
					funcHelp
					exit 1
				fi
			fi
   		;;
		o) _ANY_OSINT=1; _OPT_CHECK=1;;
		w) _WEBSERVER_OSINT=1; _OPT_CHECK=1;;
		i) _HTTPHEADER_OSINT=1; _OPT_CHECK=1;;
		m) _MAILSERVER_OSINT=1; _OPT_CHECK=1;;
		s) _SHODAN_OSINT=1; _OPT_CHECK=1;;
		t) _THEHARVESTER_OSINT=1; _OPT_CHECK=1;;
		p) _PWNED_OSINT=1; _OPT_CHECK=1;;
		z) _ZERO_DEL=1; _OPT_CHECK=1;;
		\?) echo "**Unknown option: -$OPTARG **" >&2; echo ""; funcHelp; exit 1;;
        	:) echo "**Missing option argument for -$OPTARG **" >&2; echo ""; funcHelp; exit 1;;
		*) funcHelp; exit 1;;
  	esac
  	done
	shift $(( OPTIND - 1 ))

#Check if domain set and not _ZERO_DEL option set
if [ "${_OPT_DOMAIN}" == "" ] && [ "$_ZERO_DEL" == "" ]; then
	echo "**No domain set**"
	echo ""
	funcHelp
	exit 1
fi

#Check if a option is set
if [ "${_OPT_CHECK}" == "" ]; then
	echo "**No option set**"
	echo ""
	funcHelp
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
echo "########## MG(), Version 0.6.5 - Beta (03.11.19)          ##########"
echo "####################################################################"
echo ""
echo $time

#Zero - delete all temp files
if [ "$_ZERO_DEL" == "1" ]; then
	touch ./inputs/temp/delete_$time
	rm ./inputs/temp/*
	echo "##############################"
	echo "####  TEMP FILES DELETED  ####"
	echo "##############################"
	echo ""
fi

#MX Records anzeigen - OSINT-Modul
if [ "${_ANY_MODULES}" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_MAILSERVER_OSINT" == "1" ]; then
	echo "############################"
	echo "####  MAILSERVER-CHECK  ####"
	echo "############################"
	echo ""
	func_mail_lookup
	echo ""
fi

#Mail Loadbalance Check - OSINT-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_MAILSERVER_OSINT" == "1" ]; then
	echo "##################################################"
	echo "####  HOSTNAME MAIL-SERVER-LOADBALANCE-CHECK  ####"
	echo "##################################################"
	echo ""
	func_mail_loadbalance
	echo ""
fi

#SPF Check Funktion - OSINT-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_MAILSERVER_OSINT" == "1" ]; then
	echo "#####################"
	echo "####  SPF-CHECK  ####"
	echo "#####################"
	echo ""
	func_spf_check
	echo ""
fi

#DMARC Check Funktion - OSINT-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_MAILSERVER_OSINT" == "1" ]; then
	echo "#######################"
	echo "####  DMARC-CHECK  ####"
	echo "#######################"
	echo ""
	funcDMARCcheck
	echo ""
fi

#Webserver Lookup - OSINT-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_WEBSERVER_OSINT" == "1" ]; then
	echo "###################################"
	echo "####  WEB-SERVER-LOOKUP-CHECK  ####"
	echo "###################################"
	echo ""
	func_webserver_lookup
fi

#Webserver Malware Check - OSINT-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_WEBSERVER_OSINT" == "1" ]; then
	echo "####################################"
	echo "####  WEB-SERVER-MALWARE-CHECK  ####"
	echo "####################################"
	echo ""
	func_malware_check
fi

#Webserver CAA Check - OSINT-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_WEBSERVER_OSINT" == "1" ]; then
	echo "#######################################"
	echo "####  WEB-SERVER-CAA-RECORD-CHECK  ####"
	echo "#######################################"
	echo ""
	funcCAAcheck
fi

#Webserver DNSSEC Check - OSINT-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_WEBSERVER_OSINT" == "1" ]; then
	echo "##########################################"
	echo "####  WEB-SERVER-DNSSEC-RECORD-CHECK  ####"
	echo "##########################################"
	echo ""
	funcDNSSECcheck
fi

#TheHarvester - OSINT-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_THEHARVESTER_OSINT" == "1" ]; then
	echo "#################################################"
	echo "####  MAIL and DNS Harvester - theHarvester  ####"
	echo "#################################################"
	echo ""
	func_harvester_osint
fi

#PWNED Check - OSINT-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_PWNED_OSINT" == "1" ]; then
	echo "##############################################"
	echo "####  MAIL PWNED CHECK - haveeibeenpwned  ####"
	echo "##############################################"
	echo ""
	func_pwned_check
fi

#Shodan.io Check - OSINT-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_SHODAN_OSINT" == "1" ]; then
	echo "####################################"
	echo "####  SHODAN CHECK - shodan.io  ####"
	echo "####################################"
	echo ""
	func_shodan_check
fi

#HTTP Header Check - Scan-Modul
if [ "$_ANY_MODULES" == "1" ] || [ "$_ANY_OSINT" == "1" ] || [ "$_HTTPHEADER_OSINT" == "1" ]; then
	echo "#############################"
	echo "####  HTTP HEADER CHECK  ####"
	echo "#############################"
	echo ""
	funcHttpheaderDiscovery
	funcSecurityheaderCheck
	funcHttpheaderCvedetailsCheck
	funcHttpheaderVulnCheck
fi

###################### END ######################
