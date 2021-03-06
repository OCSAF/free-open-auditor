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
funcHttpheaderDiscovery() {

#server_version_nr=Output Variable
local h_value
local h_value_version
local userAgent

userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:62.0) Gecko/20100101 Firefox/62.0"
#urlHeader=$(curl --silent --location --insecure --head --user-agent "$userAgent" $checkDomain --http1.1)

if [[ $_DOMAIN == *.*.* ]]; then
	#dig $_DOMAIN +short
	./libraries/python/httpheader.py -u http://$_DOMAIN > ./inputs/temp/http_header_$_DOMAIN-$time.txt
	#curl --user-agent "${userAgent}" -L -I -s -o ./inputs/temp/http_header_$_DOMAIN-$time.txt $_DOMAIN --http1.1
else
	#dig www.$_DOMAIN +short
	./libraries/python/httpheader.py -u http://www.$_DOMAIN > ./inputs/temp/http_header_$_DOMAIN-$time.txt
	#curl --user-agent "${userAgent}" -L -I -s -o ./inputs/temp/http_header_$_DOMAIN-$time.txt www.$_DOMAIN --http1.1
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

	h_value=$(cat ./inputs/temp/http_header_$_DOMAIN-$time.txt | grep -i "$h_file_value1" | head -n 1 | sed 's/\r$//')
	h_value2=$(cat ./inputs/temp/http_header_$_DOMAIN-$time.txt | grep -i "$h_file_value1" | head -n 2 | tail -n 1 | sed 's/\r$//')

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
	echo -e "${yON}$h_value${cOFF}"
		version_nr+=("$h_version_nr")
	elif [ "$h_value" != "$h_value2" ] && [ "$h_version_nr" != "" ]; then
		echo -e "${yON}$h_value${cOFF}"
		echo -e "${yON}$h_value2${cOFF}"
		version_nr+=("${h_version_nr[*]}")
		version_nr+=("${h_version_nr2[*]}")
	fi

done <./inputs/project/http/httpheader.txt
echo ""

echo "##############################"
echo "HTTP-Header:"
echo ""
cat ./inputs/temp/http_header_$_DOMAIN-$time.txt

}

############# Security Headers #############

funcSecurityheaderCheck() {

echo "#############################"
echo "Security-Headers:"
echo ""

while read line
do
	local shFileValue1
	local shFileColor
	local urlHeader
	local sHeaderCheck

	shFileValue1=$(echo "$line" | awk -F ';;' '{print $1}')
	shFileColor=$(echo "$line" | awk -F ';;' '{print $2}')	
	urlHeader=$(cat ./inputs/temp/http_header_$_DOMAIN-$time.txt)
	#echo $shFileColor
	
	# Check if security header is set
	sHeaderCheck=$(echo "${urlHeader}" | grep -i "$shFileValue1")
	if [ -z "$sHeaderCheck" ]; then
		if [ "$shFileColor" == "red" ]; then
    			echo -e "${rON}${shFileValue1} not set!${cOFF}"
		elif [ "$shFileColor" == "yellow" ]; then
    			echo -e "${yON}${shFileValue1} not set!${cOFF}"
		fi
	else
    		echo -e "${gON}${sHeaderCheck}${cOFF}"
	fi

done <./inputs/project/http/securityheader.txt

echo ""
}

############# Cookie Check #############

funcCookieCheck() {

local userAgent
local urlHeader
local hsts
local csp
local xframe
local xss
local xcontent
local referrer
local feature
local xpowered
local expectct

echo "#############################"
echo "Cookie Check:"
echo ""

local urlHeader
local cookie


}

########### SECURITY-HEADER-EXPLOIT-DB-CHECK ##########
funcHttpheaderVulnCheck(){

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
funcHttpheaderCvedetailsCheck(){

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

################## END ####################
