#!/bin/bash

############################################################################
################### FREE OCSAF SCAN FUNCTIONS - LIBRARY ####################
############################################################################

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


#preparing tasks
time=$(date +%d.%m.%Y-%H:%M)


########### HTTP-HEADER DISCOVERY KI-Version ###########
httpheader_discovery() {

#server_version_nr=Output Variable
local h_value
local h_value_version

if [[ $domain == *.*.* ]]; then
	#dig $domain +short
	curl -L -I -s -o ./inputs/temp/http_header_$domain-$time.txt $domain --http1.1
else
	#dig www.$domain +short
	curl -L -I -s -o ./inputs/temp/http_header_$domain-$time.txt www.$domain --http1.1
fi

echo "##############################"
echo "Unwanted information discovery:"
echo ""
while read line
do
	unset h_file_value1
	unset h_file_value2
	unset h_file_value3
	unset h_file_value4
	unset h_file_value5
	unset h_value
	unset h_value_version
	unset h_version_nr

	#h_file_value1="$(echo "$line" | awk -F ';;' '{print $1}' | sed 's/\// /' | sed 's/\-/ /' |sed 's/(/ /' | sed 's/)/ /' | sed 's/\,//' |  sed 's/\r$//g')"
	h_file_value1=$(echo "$line" | awk -F ';;' '{print $1}')
	h_file_value2=$(echo "$line" | awk -F ';;' '{print $2}')
	h_file_value3=$(echo "$line" | awk -F ';;' '{print $3}')
	h_file_value4=$(echo "$line" | awk -F ';;' '{print $4}')
	#h_file_value5=$(echo "$line" | awk -F ';;' '{print $5}')

	h_value=$(cat ./inputs/temp/http_header_$domain-$time.txt | grep -i "$h_file_value1" | head -n 1 | sed 's/\r$//')
	h_value2=$(cat ./inputs/temp/http_header_$domain-$time.txt | grep -i "$h_file_value1" | head -n 2 | tail -n 1 | sed 's/\r$//')

	#h_value_version=$(echo ${h_value[*]} | awk -F '$h_file_value1' '{print $2}')
	h_value_version=$(echo ${h_value[*]} | awk -F ' ' '{print $2}')
	h_version_nr=$(echo ${h_value_version[0]} | awk -F ' ' '{print $1}' | sed 's/\// /' | sed 's/\-/ /' |sed 's/(/ /' | sed 's/)/ /' | sed 's/\,//' |  sed 's/\r$//')
	h_value_version2=$(echo ${h_value2[*]} | awk -F ' ' '{print $2}')
	h_version_nr2=$(echo ${h_value_version2[0]} | awk -F ' ' '{print $1}' | sed 's/\// /' | sed 's/\-/ /' |sed 's/(/ /' | sed 's/)/ /' | sed 's/\,//' |  sed 's/\r$//')

#echo "TEST"
#echo $h_value
#echo $h_value2
#echo ${h_file_value1[*]}
#echo ${h_value[*]}
#echo $h_value_version
#echo $h_version_nr

	#if [ "$h_version_nr" != "" ]; then
	if [ "$h_value" == "$h_value2" ] && [ "$h_version_nr" != "" ]; then
	echo -e "\033[33m$h_value\033[0m"
		version_nr+=("$h_version_nr")
	elif [ "$h_value" != "$h_value2" ] && [ "$h_version_nr" != "" ]; then
		echo -e "\033[33m$h_value\033[0m"
		echo -e "\033[33m$h_value2\033[0m"
		version_nr+=("${h_version_nr[*]}")
		version_nr+=("${h_version_nr2[*]}")
	fi

done <./inputs/project/http/httpheader.txt
echo ""

echo "##############################"
echo "HTTP-Header:"
echo ""
cat ./inputs/temp/http_header_$domain-$time.txt
echo ""

}


########### SECURITY-HEADER-EXPLOIT-DB-CHECK ##########
httpheader_vuln_check(){

local i

for ((i=0;i<${#version_nr[*]};i++))
do
echo "######################"
echo "Check Exploit-DB with:"
echo "searchsploit ${version_nr[$i]}"
echo ""
if [ "${version_nr[$i]}" != "" ]; then
searchsploit ${version_nr[$i]}
echo ""
fi
done

}

########### SECURITY-HEADER-CVEDETAILS.COM-CHECK ##########
httpheader_cvedetails_check(){

local i

if [ "$version_nr" != "" ]; then

	for ((i=0;i<${#version_nr[*]};i++))
	do
	local version_link=$(echo "${version_nr[$i]}" | sed 's/ /\+/g') 

	echo "##################################################"
	echo "Search for vulnerabilities in the following links:"
	echo ""
	echo "https://www.cvedetails.com/google-search-results.php?q=$version_link"
	echo "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=$version_link"
	echo ""
	echo "https://securitytracker.com/search/search.html (search for ${version_nr[$i]})"
	echo "https://www.securityfocus.com/bid (search for ${version_nr[$i]})"
	echo "https://vuldb.com/?search (search for ${version_nr[$i]})"
	echo ""
	done
fi

}

############ BLACKLIST-CHECK ############
#Thanks to Agarzon, Quick Blacklist Check inspired by https://gist.github.com/agarzon/5554490
2mailserver_blcheck() {
	#OUTPUT global variable = bl_listed
	local i
	local blacklists
	local reverse_ip
	local reverse_dns
	local bl
	local list
	local blacklists=$(<./inputs/project/bl/blacklists.txt)

	for ((i=0;i<${#ip_listed[*]};i++))
	do
		reverse_ip=$(echo ${ip_listed[$i]} \
			| sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
		reverse_dns=$(dig +short -x ${ip_listed[$i]})
		
		echo IP ${ip_listed[$i]} HOST ${reverse_dns:----}
		for bl in ${blacklists} ; do
    			printf "%-60s" " ${reverse_ip}.${bl}."
    			list="$(dig +short -t a ${reverse_ip}.${bl}.)"
    			if  [ "$list" == "" ]; then
				echo -e "\033[32m${list:-OK}\033[0m"
			else
				bl_listed+=("${ip_listed[$i]}:$bl")
				echo -e "\033[31mlisted: ${list:----}\033[0m"
			fi
		done
		echo ""
	done
}
###################################
#Thanks to Navan Chauhan - https://github.com/navanchauhan/Pwned
2pwned_check() {
	local i
	local breach
	local pasteacc
	local mail_pwned

	if [ "${mail_checked[*]}" == "" ]; then
	
		echo -e "\033[32mKeine E-Mailadressen zum prüfen vorhanden.\033[0m"
	else
		for ((i=0;i<${#mail_checked[*]};i++))
		do 
			echo "Checking if ${mail_checked[$i]} have been Pwned:"
		
			curl -s -o breach.json "https://haveibeenpwned.com/api/v2/breachedaccount/${mail_checked[$i]}"
			curl -s -o pasteacc.json "https://haveibeenpwned.com/api/v2/pasteaccount/${mail_checked[$i]}"

			jq ".[]" breach.json > semibreach.json 
			jq .Title semibreach.json > breach.txt
			jq ".[]" pasteacc.json > semipaste.json 
			jq .Title semipaste.json > pasteacc.txt
		
			if [[ -s breach.txt ]]; then	
				echo -e "\033[31mPWNED! at:\033[0m"
				breach="$(sed 's/\"//g' breach.txt)"
				mail_pwned=($(echo ${mail_checked[$i]}))
				echo $breach
			fi
		
			if [[ -s pasteacc.txt ]]; then	
				echo -e "\033[31mPaste in!!:\033[0m"
				pasteacc="$(sed 's/\"//g' pasteacc.txt)"
				mail_pwned=($(echo ${mail_checked[$i]}))
				echo $pasteacc
			fi

			if ! [ -s breach.txt ] && ! [ -s pasteacc.txt ]; then	
				echo -e "\033[32mOK\033[0m"
			fi
			rm breach.json
			rm semibreach.json
			rm breach.txt
			rm pasteacc.json
			rm semipaste.json
			rm pasteacc.txt
		
			echo "----------------------"
			sleep 1.5
		done
	fi
	echo ""
}
#########################################
