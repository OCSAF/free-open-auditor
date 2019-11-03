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


############# MX-IP Check ################
func_mail_lookup() {	
	#INPUT global variable = _DOMAIN
	#OUTPUT global variable = mailserver_ipv4
	#OUTPUT global variable = ip_listed
	
	local i
	local reverse_ip
	local reverse_dns
	local bl
	local list
	local mail
	local mailsrv
	local reverse
	local tld
	local geotld
	local geoCheck
	local mailserver_ipv4
	
	#Thanks to Agarzon, Quick Blacklist Check inspired by https://gist.github.com/agarzon/5554490
	
	local blacklists=$(<./inputs/project/bl/blacklists.txt)
	
	echo "MX-Records:"
	dig -t mx $_DOMAIN +noall +answer | grep "IN" | grep "MX" | sort -V
	echo ""
	
	mail=($(host -t mx $_DOMAIN | sort -V | cut -d " " -f7))
	mailsrv="$(for((i=0;i<${#mail[*]};i++));do dig +noall +answer ${mail[$i]}; done)" #speichert nur in Wert[0]
	mailserver_ipv4=($(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' <<< "$mailsrv")) #speichert nur IPs

	if [ "${mailserver_ipv4[0]}" == "" ]
		then
		echo -e "${rON}NO MAIL SERVER FOUND!:${cOFF}"
	elif [ "${mailserver_ipv4[1]}" == "" ]
		then
		echo -e "${yON}NO REDUNDANT MAIL SERVER FOUND!:${cOFF}"
	elif [ "${mailserver_ipv4[0]}" != "${mailserver_ipv4[1]}" ]
		then
		echo -e "${gON}REDUNDANT MAIL SERVER FOUND:${cOFF}"
	elif [ "${mailserver_ipv4[0]}" != "${mailserver_ipv4[2]}" ]
		then
		echo -e "${gON}REDUNDANT MAIL SERVER FOUND:${cOFF}"
	else
		echo -e "${yON}NO REDUNDANT MAIL SERVER FOUND!:${cOFF}"
	fi	
	
	#echo ${mail[*]}
	for((i=0;i<${#mail[*]};i++)) 
	do
		dig +noall +answer ${mail[$i]}
	done
	echo ""

	for((i=0;i<${#mailserver_ipv4[*]};i++))
	do 
		test_geoip=$(echo ${ip_listed[*]} | grep "${mailserver_ipv4[$i]}")
		if [ "$ip_listed" == "" ]; then
			echo "Mailserver" ${mailserver_ipv4[$i]}":"
			geoiplookup ${mailserver_ipv4[$i]}
			
			tld=$(echo $_DOMAIN | sed -e 's/^.*\.//' | tr [:lower:] [:upper:])
			geotld=($(geoiplookup ${mailserver_ipv4[$i]} | grep "GeoIP Country Edition:" | cut -d "," -f1 | cut -d " " -f4))
			geoCheck="$(echo ${geotld[*]} | sed -e "s/$tld//g" | sed 's/^[ \t]*//')"
			if [ "${geoCheck[*]}" == "" ]; then
				echo -e "Server location: ${gON}${geotld[*]}-Server in the same country as the domain extension.${cOFF} [$tld]"
			else
				echo -e "Server location: ${yON}${geotld[*]}-Server may not be in the same country as the domain extension.${cOFF} [$tld]"
			fi
			
			ip_listed+=("${mailserver_ipv4[$i]}")
			reverse_ip=$(echo ${mailserver_ipv4[$i]} \
				| sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
			reverse_dns=$(dig +short -x ${mailserver_ipv4[$i]})
	
			_abuse=$(wget -q -O- --post-data="host=${mailserver_ipv4[$i]}" https://urlhaus-api.abuse.ch/v1/host/)
			_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
			_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')

			echo Blacklist-Check: ${reverse_dns:----}
			
			if [ "${_abusestat}" == "no_results" ]; then	
				printf "%-60s" " urlhaus-api.abuse.ch (${mailserver_ipv4[$i]})"
				echo -e "${gON}OK${cOFF}"
			else
				printf "%-60s" " urlhaus-api.abuse.ch (${mailserver_ipv4[$i]})"
				echo -e "${rON}listed: ${_abuseref}${cOFF}"
			fi
	
			for bl in ${blacklists} ; do
    				printf "%-60s" " ${reverse_ip}.${bl}."
    				list="$(dig +short -t a ${reverse_ip}.${bl}.)"
    				if  [ "$list" == "" ]; then
					echo -e "${gON}${list:-OK}${cOFF}"
				else
					bl_listed+=("${ip_listed[$i]}:$bl")
					echo -e "${rON}listed: ${list:----}${cOFF}"
				fi
			done
			echo ""

		elif [ "$test_geoip" == "" ]; then
			echo "Mailserver" ${mailserver_ipv4[$i]}":"
			geoiplookup ${mailserver_ipv4[$i]}
			
			tld=$(echo $_DOMAIN | sed -e 's/^.*\.//' | tr [:lower:] [:upper:])
			geotld=($(geoiplookup ${mailserver_ipv4[$i]} | grep "GeoIP Country Edition:" | cut -d "," -f1 | cut -d " " -f4))
			geoCheck="$(echo ${geotld[*]} | sed -e "s/$tld//g" | sed 's/^[ \t]*//')"
			if [ "${geoCheck[*]}" == "" ]; then
				echo -e "Server location: ${gON}${geotld[*]}-Server in the same country as the domain extension.${cOFF} [$tld]"
			else
				echo -e "Server location: ${yON}${geotld[*]}-Server may not be in the same country as the domain extension.${cOFF} [$tld]"
			fi
			
			ip_listed+=("${mailserver_ipv4[$i]}")
			reverse_ip=$(echo ${mailserver_ipv4[$i]} \
				| sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
			reverse_dns=$(dig +short -x ${mailserver_ipv4[$i]})
		
			_abuse=$(wget -q -O- --post-data="host=${mailserver_ipv4[$i]}" https://urlhaus-api.abuse.ch/v1/host/)
			_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
			_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')

			echo Blacklist-Check: ${reverse_dns:----}
			
			if [ "${_abusestat}" == "no_results" ]; then	
				printf "%-60s" " urlhaus-api.abuse.ch (${mailserver_ipv4[$i]})"
				echo -e "${gON}OK${cOFF}"
			else
				printf "%-60s" " urlhaus-api.abuse.ch (${mailserver_ipv4[$i]})"
				echo -e "${rON}listed: ${_abuseref}${cOFF}"
			fi
	
			for bl in ${blacklists} ; do
    				printf "%-60s" " ${reverse_ip}.${bl}."
    				list="$(dig +short -t a ${reverse_ip}.${bl}.)"
    				if  [ "$list" == "" ]; then
					echo -e "${gON}${list:-OK}${cOFF}"
				else
					bl_listed+=("${ip_listed[$i]}:$bl")
					echo -e "${rON}listed: ${list:----}${cOFF}"
				fi
			done
			echo ""
		fi
	done
}

########### WEBSERVER #############
func_webserver_lookup() {
	#INPUT global variable = _DOMAIN
	#INPUT global variable = ip_listed
	#OUTPUT global variable = arecord
	#OUTPUT global variable = ip_listed

	local i
	local arecord
	local arecord2
	local reverse
	local reverse2
	local reverse_ip
	local reverse_dns
	local reverse_check
	local tld
	local geotld
	local geoCheck
	local i
	local alias

	#Thanks to Agarzon, Quick Blacklist Check inspired by https://gist.github.com/agarzon/5554490
	local blacklists=$(<./inputs/project/bl/blacklists.txt)

	arecord=($(host -t a $_DOMAIN | cut -d " " -f4))
	reverse="$(for((i=0;i<${#arecord[*]};i++));do host ${arecord[$i]} | cut -d " " -f5; done)"

	for((i=0;i<${#arecord[*]};i++))
	do
		if [ "${arecord[$i]}" == "A" ]; then
			
			echo "No A-Record for $_DOMAIN:"
			alias="$(host -t a www.$_DOMAIN | grep alias)"
			echo "Alias: $alias"
			arecord2=($(host -t a www.$_DOMAIN | grep address | cut -d " " -f4))
			reverse2="$(host ${arecord2[*]} | cut -d " " -f5)"
				ip_listed+=("$arecord2")
				echo "Host-IP: " $arecord2
				geoiplookup $arecord2
		
				tld=$(echo $_DOMAIN | sed -e 's/^.*\.//' | tr [:lower:] [:upper:])
				geotld=($(geoiplookup ${arecord2[$i]} | grep "GeoIP Country Edition:" | cut -d "," -f1 | cut -d " " -f4))
				geoCheck="$(echo ${geotld[*]} | sed -e "s/$tld//g" | sed 's/^[ \t]*//')"
				if [ "${geoCheck[*]}" == "" ]; then
					echo -e "Server location: ${gON}${geotld[*]}-Server in the same country as the domain extension.${cOFF} [$tld]"
				else
					echo -e "Server location: ${yON}${geotld[*]}-Server may not be in the same country as the domain extension.${cOFF} [$tld]"
				fi

				echo "Reverse-Lookup: " $reverse2
				reverse_ip=$(echo ${arecord2[$i]} \
					| sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
				reverse_dns=$(dig +short -x ${arecord2[$i]})
			
				_abuse=$(wget -q -O- --post-data="host=${arecord2[$i]}" https://urlhaus-api.abuse.ch/v1/host/)
				_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
				_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')

				echo BLACKLIST-CHECK: $arecord2
			
				if [ "${_abusestat}" == "no_results" ]; then	
					printf "%-60s" " urlhaus-api.abuse.ch (${arecord2[$i]})"
					echo -e "${gON}OK${cOFF}"
				else
					printf "%-60s" " urlhaus-api.abuse.ch (${arecord2[$i]})"
					echo -e "${rON}listed: ${_abuseref}${cOFF}"
				fi
	
				for bl in ${blacklists} ; do
    					printf "%-60s" " ${reverse_ip}.${bl}."
    					local list="$(dig +short -t a ${reverse_ip}.${bl}.)"
    					if  [ "$list" == "" ]; then
						echo -e "${gON}${list:-OK}${cOFF}"
					else
						bl_listed+=("${arecord[$i]}:$bl")
						echo -e "${rON}listed: ${list:----}${cOFF}"
					fi
				done
		else
			if [ "${arecord[$i]}" != "alias" ]; then
				ip_listed+=("${arecord[$i]}")
			
				echo "Host-IP: " ${arecord[$i]}
				geoiplookup ${arecord[$i]}
				reverse3="$(host ${arecord[$i]} | cut -d " " -f5)"
				tld=$(echo $_DOMAIN | sed -e 's/^.*\.//' | tr [:lower:] [:upper:])
				geotld=($(geoiplookup ${arecord[$i]} | grep "GeoIP Country Edition:" | cut -d "," -f1 | cut -d " " -f4))
				geoCheck="$(echo ${geotld[*]} | sed -e "s/$tld//g" | sed 's/^[ \t]*//')"
				if [ "${geoCheck[*]}" == "" ]; then
					echo -e "Server location: ${gON}${geotld[*]}-Server in the same country as the domain extension.${cOFF} [$tld]"
				else
					echo -e "Server location: ${yON}${geotld[*]}-Server may not be in the same country as the domain extension.${cOFF} [$tld]"
				fi
	
				echo "Reverse-Lookup: " $reverse3
				reverse_ip=$(echo ${arecord[$i]} \
					| sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
				reverse_dns=$(dig +short -x ${arecord[$i]})
				
				_abuse=$(wget -q -O- --post-data="host=${arecord[$i]}" https://urlhaus-api.abuse.ch/v1/host/)
				_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
				_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')

				echo BLACKLIST-CHECK: ${arecord[$i]}
			
				if [ "${_abusestat}" == "no_results" ]; then	
					printf "%-60s" " urlhaus-api.abuse.ch (${arecord[$i]})"
					echo -e "${gON}OK${cOFF}"
				else
					printf "%-60s" " urlhaus-api.abuse.ch (${arecord[$i]})"
					echo -e "${rON}listed: ${_abuseref}${cOFF}"
				fi
	
				for bl in ${blacklists} ; do
    					printf "%-60s" " ${reverse_ip}.${bl}."
    					local list="$(dig +short -t a ${reverse_ip}.${bl}.)"
    					if  [ "$list" == "" ]; then
						echo -e "${gON}${list:-OK}${cOFF}"
					else
						bl_listed+=("${arecord[$i]}:$bl")
						echo -e "${rON}listed: ${list:----}${cOFF}"
					fi
				done
			fi
		fi
			echo ""
	done
}

############# DOMAIN Malware-Check KI-Version ##############

func_malware_check() {

local line
local web_check
local web_check2
local dns_file_value1
local dns_file_value2

if [[ $_DOMAIN == *.*.* ]]; then
	echo "DNS Malware-Site-Check for $_DOMAIN:"
	
	_abuse=$(wget -q -O- --post-data="host=${_DOMAIN}" https://urlhaus-api.abuse.ch/v1/host/)
	_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
	_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')
		
	echo -e "Tested URL: ${yON}${_DOMAIN}${cOFF}"

	if [ "${_abusestat}" == "no_results" ]; then
		_domain=$(echo ${_DOMAIN} | sed -r 's/.*\.([^.]+\.[^.]+)$/\1/')	
			
		unset _abuse _abusestat _abuseref
		_abuse=$(wget -q -O- --post-data="host=${_domain}" https://urlhaus-api.abuse.ch/v1/host/)
		_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
		_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')
			
		if [ "${_abusestat}" == "no_results" ]; then
			printf "%-60s" " urlhaus-api.abuse.ch (${_DOMAIN})"
			echo -e "${gON}OK${cOFF}"
		else
			printf "%-60s" " urlhaus-api.abuse.ch (${_domain})"
			echo -e "${rON}listed: ${_abuseref}${cOFF}"
		fi
	else
		printf "%-60s" " urlhaus-api.abuse.ch (${_DOMAIN})"
		echo -e "${rON}listed: ${_abuseref}${cOFF}"
	fi
	
	while read line
	do
		unset web_check
		unset web_check2
		unset dns_file_value1
		unset dns_file_value2

		dns_file_value1=$(echo "$line" | awk -F ';;' '{print $1}')
		dns_file_value2=$(echo "$line" | awk -F ';;' '{print $2}')

		web_check=$(dig $_DOMAIN @$dns_file_value1 +recurse +short)
		printf "%-60s" " $dns_file_value2 ($dns_file_value1)"
		if [ "$web_check" != "" ]; then
			echo -e "${gON}OK${cOFF}"
		else
			echo -e "${rON}listed${cOFF}"
		fi
	done <./inputs/project/bl/malware_dnslists.txt
	echo ""
else
	echo "DNS Malware-Site-Check for www.$_DOMAIN:"
	
	_abuse=$(wget -q -O- --post-data="host=www.${_DOMAIN}" https://urlhaus-api.abuse.ch/v1/host/)
	_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
	_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')
		
	echo -e "Tested URL: ${yON}www.${_DOMAIN}${cOFF}"

	if [ "${_abusestat}" == "no_results" ]; then
		_domain=$(echo www.${_DOMAIN} | sed -r 's/.*\.([^.]+\.[^.]+)$/\1/')	
			
		unset _abuse _abusestat _abuseref
		_abuse=$(wget -q -O- --post-data="host=${_domain}" https://urlhaus-api.abuse.ch/v1/host/)
		_abusestat=$(echo ${_abuse} | jq '.query_status' | sed 's/\"//g')
		_abuseref=$(echo ${_abuse}| jq '.urlhaus_reference' | sed 's/\"//g')
			
		if [ "${_abusestat}" == "no_results" ]; then
			printf "%-60s" " urlhaus-api.abuse.ch (www.${_DOMAIN})"
			echo -e "${gON}OK${cOFF}"
		else
			printf "%-60s" " urlhaus-api.abuse.ch (${_domain})"
			echo -e "${rON}listed: ${_abuseref}${cOFF}"
		fi
	else
		printf "%-60s" " urlhaus-api.abuse.ch (www.${_DOMAIN})"
		echo -e "${rON}listed: ${_abuseref}${cOFF}"
	fi

	while read line
	do
		unset web_check
		unset web_check2
		unset dns_file_value1
		unset dns_file_value2

		dns_file_value1=$(echo "$line" | awk -F ';;' '{print $1}')
		dns_file_value2=$(echo "$line" | awk -F ';;' '{print $2}')

		web_check=$(dig www.$_DOMAIN @$dns_file_value1 +recurse +short)
		printf "%-60s" " $dns_file_value2 ($dns_file_value1)"
		if [ "$web_check" != "" ]; then
			echo -e "${gON}OK${cOFF}"
		else
			echo -e "${rON}listed${cOFF}"
		fi
	done <./inputs/project/bl/malware_dnslists.txt
	echo ""
fi
}

################ SPF KI Version #################
func_spf_check() {
	#spf_value = global variable
	local i
	local spf
	local _spf_redirect
	local _spf_redirect_check
	local _spf_redirect_value
	local _spf_record
	local _spf_file_value1
	local _spf_file_value2
	local _spf_file_value3
	local _spf_file_value4
	local _spf_file_value5
	local _spf_grep
	local _spf_record
	
	spf=$(host -t txt $_DOMAIN | grep -i "spf" | awk -F 'text' '{print $2}')
	spf_value=($(echo $spf | grep -oE " .all| redirect"))

	if [ "$spf" != "" ]; then	
		echo $spf
		
		while read line
		do
			unset _spf_file_value1
			unset _spf_file_value2
			unset _spf_file_value3
			unset _spf_file_value4
			unset _spf_file_value5
			unset _spf_grep
			unset _spf_record

			_spf_file_value1=$(echo "$line" | awk -F '::' '{print $1}')
			_spf_file_value2=$(echo "$line" | awk -F '::' '{print $2}')
			_spf_file_value3=$(echo "$line" | awk -F '::' '{print $3}')
			_spf_file_value4=$(echo "$line" | awk -F '::' '{print $4}')
			_spf_file_value5=$(echo "$line" | awk -F '::' '{print $5}')
			
			if [ "$spf_value" != "" ]; then
				_spf_record=$(echo $spf | awk -F '"' '{print $2}' | awk -F "$_spf_file_value1" '{print $1}')
			else
				_spf_record=$(echo $spf | awk -F '"' '{print $2}')
			fi
			
			case $spf_value in
				"$_spf_file_value1")
					echo ""
					if [ "$_spf_file_value2" == "green" ]; then
						echo -e "${gON}$_spf_file_value3${cOFF}"
					elif [ "$_spf_file_value2" == "yellow" ]; then
						echo -e "${yON}$_spf_file_value3${cOFF}"
					elif [ "$_spf_file_value2" == "red" ]; then
						echo -e "${rON}$_spf_file_value3${cOFF}"
					elif [ "$_spf_file_value2" == "" ]; then
						echo $_spf_file_value3
					fi

					if [ "$_spf_file_value4" != "" -a "$_spf_file_value5" != "" ]; then
						echo Proposal hardfail: '"'$_spf_record -all'"'
						echo Proposal softfail: '"'$_spf_record ~all'"'
					elif [ "$_spf_file_value4" != "" -a "$_spf_file_value5" == "" ]; then
						echo Proposal softfail: '"'$_spf_record -all'"'
					fi
					;;
				redirect)
					_spf_redirect=($(echo $spf | awk -F "redirect=" '{print $2}' | cut -d '"' -f1))
					_spf_redirect_check=$(host -t txt $_spf_redirect | grep -i "spf")
					_spf_redirect_value=($(echo $_spf_redirect_check | grep -oE " .all| redirect"))
					
					if [ "$_spf_redirect_check" != "" ]; then
						case $_spf_redirect_value in
							"$_spf_file_value1")
								echo "SPF redirected to:"
								echo $_spf_redirect_check
								echo ""
								if [ "$_spf_file_value2" == "green" ]; then
									echo -e "${gON}$_spf_file_value3${cOFF}"
								elif [ "$_spf_file_value2" == "yellow" ]; then
									echo -e "${yON}$_spf_file_value3${cOFF}"
								elif [ "$_spf_file_value2" == "red" ]; then
									echo -e "${rON}$_spf_file_value3${cOFF}"
								elif [ "$_spf_file_value2" == "" ]; then
									echo $_spf_file_value3
								fi

								if [ "$_spf_file_value4" != "" -a "$_spf_file_value5" != "" ]; then
									echo Proposal hardfail: '"'$_spf_record -all'"'
									echo Proposal softfail: '"'$_spf_record ~all'"'
								elif [ "$_spf_file_value4" != "" -a "$_spf_file_value5" == "" ]; then
									echo Proposal softfail: '"'$_spf_record -all'"'
								fi
						esac
					else
						echo "SPF redirected to:"
						echo -e "${rON}*No SPF entry: There is a risk of phishing emails. Add SPF entry!*${cOFF}"
					fi
					;;
			esac
		done <./inputs/project/spf/spf.txt

	else	
		echo -e "${rON}*No SPF entry: There is a risk of phishing emails. Add SPF entry!*${cOFF}"
	fi

	echo "Details: https://de.wikipedia.org/wiki/Sender_Policy_Framework"
}

################ DMARC KI Version #################
funcDMARCcheck() {
	local _dmarc
	
	_dmarc=$(dig +noall +answer -t txt _dmarc.$_DOMAIN)
	if [ -z "${_dmarc}" ]; then
    		echo -e "${yON}DMARC not set!${cOFF}"
	else
    		echo -e "${gON}DMARC is set:${cOFF}" 
		echo ${_dmarc}
	fi
	
	echo ""
	echo "Details: https://en.wikipedia.org/wiki/DMARC"
	echo ""
}

################ DNSSEC KI Version #################
funcDNSSECcheck() {
	local _dnssec
	
	_dnssec=$(dig +noall +answer +dnssec $_DOMAIN | grep -i "RRSIG")
	if [ -z "${_dnssec}" ]; then
    		echo -e "${yON}DNSSEC not set!${cOFF}"
	else
    		echo -e "${gON}DNSSEC is set:${cOFF}" 
		echo ${_dnssec}
	fi
	
	echo ""
	echo "Details: https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions"
	echo ""
}

################ CAA KI Version #################
funcCAAcheck() {
	local _caa
	
	_caa=$(dig +noall +answer -t caa $_DOMAIN)
	if [ -z "${_caa}" ]; then
    		echo -e "${yON}CAA not set!${cOFF}"
	else
    		echo -e "${gON}CAA is set:${cOFF}" 
		echo ${_caa}
	fi
	
	echo ""
	echo "Details: https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization"
	echo ""
}


############### MAIL-HARVESTER ###############
#Thanks to TheHarvester - https://github.com/laramies/theHarvester
func_harvester_osint() {
	#_mail_checked = global variable
	#_mail_num = global variable
	local _i
	local _mail_addr
	local _dns_enum
	local _dns_checked
	local _dns_num

	_mail_addr=($(theHarvester -d $_DOMAIN -l 200 -b google \
		| grep @ \
		| grep "[\.@]$_DOMAIN"))

	echo "-----------------------"
	
	if [ "${_mail_addr[*]}" != "" ]; then
		for ((_i=0;_i<${#_mail_addr[*]};_i++))
		do 
			_mail_checked+=($(echo ${_mail_addr[$_i]} | grep "[\.@]$_DOMAIN"))
		done
		
		_mail_num=$(echo ${_mail_checked[*]} | wc -w)
		
		if [ "${_mail_checked[*]}" != "" ]; then
			if [ "${_mail_checked[1]}" == "" ]; then
				echo -e "${yON}$_mail_num Email address found!${cOFF}"
			else
				echo -e "${yON}$_mail_num Email addresses found!${cOFF}"
			fi

			for ((i=0;i<${#_mail_checked[*]};i++))
			do 
				echo  ${_mail_checked[$i]}
			done	
		
		fi
	
	else
		echo -e "${gON}No email address found.${cOFF}"
	fi
	
	echo "-----------------------"
	echo ""
	
	_dns_enum=($(theHarvester -d $_DOMAIN -b dnsdumpster,crtsh \
		| grep -v '[*]' \
		| grep : \
		| grep $_DOMAIN))
	
	echo "-----------------------"
	
	if [ "${_dns_enum[*]}" != "" ]; then
		for ((_i=0;_i<${#_dns_enum[*]};_i++))
		do 
			_dns_checked+=($(echo ${_dns_enum[$_i]}))
		done
	
		_dns_num=$(echo ${_dns_checked[*]} | wc -w)
		
		if [ "${_dns_checked[*]}" != "" ]; then
			if [ "${_dns_checked[1]}" == "" ]; then
				echo -e "${yON}$_dns_num host found!${cOFF}"
			else
				echo -e "${yON}$_dns_num hosts found!${cOFF}"
			fi

			for ((i=0;i<${#_dns_checked[*]};i++))
			do 
				echo  ${_dns_checked[$i]}
			done	
		
		fi
	
	else
		echo -e "${gON}No hosts found with DNS enumeration.${cOFF}"
	fi
	
	echo "-----------------------"
	echo ""

}

################### PWNED-CHECK ####################
#Thanks to Navan Chauhan for the code inspiration. - https://github.com/navanchauhan/Pwned
func_pwned_check() {
	local pwned
	local pasted
	local pastedid
	local i
	
	if [ "${_mail_checked[*]}" == "" ]; then
	
		echo -e "${gON}No email address available to check.${cOFF}"
	else
		for ((i=0;i<${#_mail_checked[*]};i++)); do 
			echo "Check ${_mail_checked[$i]}:"
			pwned=$(wget -q -O- https://haveibeenpwned.com/api/v2/breachedaccount/${_mail_checked[$i]} | jq '.[]' | jq '.Title')
			pasted=$(wget -q -O- https://haveibeenpwned.com/api/v2/pasteaccount/${_mail_checked[$i]} | jq '.[]' | jq '.Source')
			pastedid=$(wget -q -O- https://haveibeenpwned.com/api/v2/pasteaccount/${_mail_checked[$i]} | jq '.[]' | jq '.Id')
	
			if [ "${pwned}" != "" ]; then	
				echo -e "${rON}PWNED!:${cOFF} "${pwned}
			fi
		
			if [ "${pasted}" != "" ]; then
				echo ""	
				echo -e "${rON}PASTED!:${cOFF} "${pasted}
				echo "PasteID: "${pastedid}
			fi

			if [ "${pwned}" == "" ] && [ "${pasted}" == "" ]; then	
				echo -e "${gON}OK${cOFF} - Not listed"
			fi

			echo "--------------------------------------------"
			echo ""
			sleep 1.5
		done
	fi
	echo ""
}

################### SHODAN.IO-API #####################
func_shodan_check() {	
	#ip_listed = global variable (input)
	local i
	local reverse_dns
	local shodan_req

	for ((i=0;i<${#ip_listed[*]};i++))
	do
		reverse_dns=$(dig +short -x ${ip_listed[$i]})
		echo IP ${ip_listed[$i]} HOST ${reverse_dns:----}
		shodan_req=($(shodan host ${ip_listed[$i]}))
		echo ""
	done
}

################# MAILSERVER REDUNDANZ CHECK ###############
func_mail_redundanz() {
	local mail
	local mail2
	local mail3
	local mail4
	local mail_check_ipv4
	local mail2_check_ipv4
	local mail3_check_ipv4
	local mail4_check_ipv4


if [ "${mailCheckIPv4[0]}" == "" ]
	then
	echo -e "${rON}*NO MAIL SERVER FOUND!*${cOFF}"
elif [ "${mailCheckIPv4[1]}" == "" ]
	then
	echo -e "${yON}*NO REDUNDANT MAIL SERVER FOUND!*${cOFF}"
elif [ "${mailCheckIPv4[0]}" != "${mailCheckIPv4[1]}" ]
	then
	echo -e "${gON}*REDUNDANT MAIL SERVER FOUND.*${cOFF}"
elif [ "${mailCheckIPv4[0]}" != "${mailCheckIPv4[2]}" ]
	then
	echo -e "${gON}*REDUNDANT MAIL SERVER FOUND*${cOFF}"
else
	echo -e "${yON}*NO REDUNDANT MAIL SERVER FOUND!*${cOFF}"
fi

#Auf Online Mail-Dienste prüfen
mailOnline=$(echo $mail | cut -d "." -f2-6)
#echo "MailDIENST: $mailOnline" #Check für case Eintrag
case $mailOnline in
	mail.protection.outlook.com.)	echo "Microsoft Exchange Online / Office365 found."
		;;
	l.google.com.)			echo "Google MAIL (Gmail) found."
		;;
esac
echo ""
}

################# MAILSERVER LOADBALANCE CHECK ###############
func_mail_loadbalance() {
	local mx_mail
	local mail2
	local mail3
	local mail4
	local check1
	local check2
	local check3
	
	mx_mail=($(host -t mx $_DOMAIN | sort -V | cut -d " " -f7))
	mail2="$(for((i=0;i<${#mx_mail[*]};i++));do dig +noall +answer ${mx_mail[$i]}; done)" #speichert nur in Wert[0]
	check1=($(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' <<< "$mail2")) #speichert nur IPs
	sleep 1.5
	mail3="$(for((i=0;i<${#mx_mail[*]};i++));do dig +noall +answer ${mx_mail[$i]}; done)"
	check2=($(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' <<< "$mail3"))
	sleep 1.5
	mail4="$(for((i=0;i<${#mx_mail[*]};i++));do dig +noall +answer ${mx_mail[$i]}; done)"
	check3=($(grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' <<< "$mail4"))

if [ "${check1[*]}" != "${check2[*]}" ]
	then
	echo -e "${gON}*Mail server host-name load-balancing found! (3 DNS-Queries)*${cOFF}"
	echo -e "${gON}DNS-Query 1:${cOFF}" ${check1[*]}
	echo -e "${gON}DNS-Query 2:${cOFF}" ${check2[*]}
	echo "DNS-Query 3:" ${check3[*]}
elif [ "${check1[*]}" != "${check3[*]}" ]
	then
	echo -e "${gON}*Mail server host-name load-balancing found! (3 DNS-Queries)*${cOFF}"
	echo -e "${gON}DNS-Query 1:${cOFF}" ${check1[*]}
	echo "DNS-Query 2:" ${check2[*]}
	echo -e "${gON}DNS-Query 3:${cOFF}" ${check3[*]}
elif [ "${check2[*]}" != "${check3[*]}" ]
	then
	echo -e "${gON}*Mail server host-name load-balancing found!(3 DNS-Queries)*${cOFF}"
	echo "DNS-Query 1:" ${check1[*]}
	echo -e "${gON}DNS-Query 2:${cOFF}" ${check2[*]}
	echo -e "${gON}DNS-Query 3:${cOFF}" ${check3[*]}
else
	echo "*No mail server load-balancing found. (3 DNS-Queries)*"
	echo "Repeat the script for higher reliability!"
fi
}

##################### END #####################
