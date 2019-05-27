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
mail_lookup() {	
	#INPUT global variable = domain
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
	dig -t mx $domain +noall +answer | grep "IN" | grep "MX" | sort -V
	echo ""
	
	mail=($(host -t mx $domain | sort -V | cut -d " " -f7))
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
			
			tld=$(echo $domain | sed -e 's/^.*\.//' | tr [:lower:] [:upper:])
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
		
			echo Blacklist-Check: ${reverse_dns:----}
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
			
			tld=$(echo $domain | sed -e 's/^.*\.//' | tr [:lower:] [:upper:])
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
		
			echo Blacklist-Check: ${reverse_dns:----}
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
###################################

########### WEBSERVER #############
webserver_lookup() {
	#INPUT global variable = domain
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

	arecord=($(host -t a $domain | cut -d " " -f4))
	reverse="$(for((i=0;i<${#arecord[*]};i++));do host ${arecord[$i]} | cut -d " " -f5; done)"

	for((i=0;i<${#arecord[*]};i++))
	do
		if [ "${arecord[$i]}" == "A" ]; then
			
			echo "No A-Record for $domain:"
			alias="$(host -t a www.$domain | grep alias)"
			echo "Alias: $alias"
			arecord2=($(host -t a www.$domain | grep address | cut -d " " -f4))
			reverse2="$(host ${arecord2[*]} | cut -d " " -f5)"
				ip_listed+=("$arecord2")
				echo "Host-IP: " $arecord2
				geoiplookup $arecord2
		
				tld=$(echo $domain | sed -e 's/^.*\.//' | tr [:lower:] [:upper:])
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
				echo BLACKLIST-CHECK: $arecord2
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
				tld=$(echo $domain | sed -e 's/^.*\.//' | tr [:lower:] [:upper:])
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
				echo BLACKLIST-CHECK: ${arecord[$i]}
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
###################################

############# DOMAIN Malware-Check KI-Version ##############

malware_check() {

local line
local web_check
local web_check2
local dns_file_value1
local dns_file_value2

if [[ $domain == *.*.* ]]; then
	echo "DNS Malware-Site-Check for $domain:"
	
	while read line
	do
		unset web_check
		unset web_check2
		unset dns_file_value1
		unset dns_file_value2

		dns_file_value1=$(echo "$line" | awk -F ';;' '{print $1}')
		dns_file_value2=$(echo "$line" | awk -F ';;' '{print $2}')

		web_check=$(dig $domain @$dns_file_value1 +recurse +short)
		printf "%-60s" " $dns_file_value2 ($dns_file_value1)"
		if [ "$web_check" != "" ]; then
			echo -e "${gON}OK${cOFF}"
		else
			echo -e "${rON}listed${cOFF}"
		fi
	done <./inputs/project/bl/malware_dnslists.txt
	echo ""
else
	echo "DNS Malware-Site-Check for www.$domain:"

	while read line
	do
		unset web_check
		unset web_check2
		unset dns_file_value1
		unset dns_file_value2

		dns_file_value1=$(echo "$line" | awk -F ';;' '{print $1}')
		dns_file_value2=$(echo "$line" | awk -F ';;' '{print $2}')

		web_check=$(dig www.$domain @$dns_file_value1 +recurse +short)
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


#############################################################

############# DOMAIN Adult-Check ##############

#adult_check() {

#local line
#local web_check
#local web_check2
#local dns_file_value1
#local dns_file_value2


#echo "DNS Adult-Site-Check for $domain:"
	
#	while read line
#	do
#		unset web_check

#		web_check=$(dig $domain 185.228.168.168 +recurse +short)
#		printf "%-60s" " Clean Browsing (185.228.168.168)"
#		if [ "$web_check" != "" ]; then
#			echo -e "\033[32mOK\033[0m"
#		else
#			echo -e "\033[31mlisted\033[0m"
#		fi
#	done <./inputs/project/bl/malware_dnslists.txt
#	echo ""
#else
#	echo "DNS Malware-Site-Check für www.$domain:"
#
#	while read line
#	do
#		unset web_check
#		unset web_check2
#		unset dns_file_value1
#	fi
#	}

################## GEO-IP ################
geoip_check() {
	#INPUT globale variable = mailserver_ipv4
	#INPUT globale variable = arecord
	local i
	local test_geoip
	local ip_listed

	for((i=0;i<${#mailserver_ipv4[*]};i++))
	do 
		test_geoip=$(echo ${ip_listed[*]} | grep "${mailserver_ipv4[$i]}")
		if [ "$ip_listed" == "" ]; then
			echo "Mailserver" ${mailserver_ipv4[$i]}":"
			geoiplookup ${mailserver_ipv4[$i]}
			ip_listed+=("${mailserver_ipv4[$i]}")
		elif [ "$test_geoip" == "" ]; then
			echo "Mailserver" ${mailserver_ipv4[$i]}":"
			geoiplookup ${mailserver_ipv4[$i]}
			ip_listed+=("${mailserver_ipv4[$i]}")
		fi
		echo ""
	done
	
	local i=()
	for((i=0;i<${#arecord[*]};i++))
	do 
			echo "A-Host" ${arecord[$i]}":"
			geoiplookup ${arecord[$i]}
			echo ""
	done
}

################ SPF KI Version #################
spf_check() {
	#spf_value = global variable
	local i
	local spf
	local spf_redirect
	local spf_redirect_check
	local spf_redirect_value
	local spf_record
	local spf_file_value1
	local spf_file_value2
	local spf_file_value3
	local spf_file_value4
	local spf_file_value5
	local spf_grep
	local spf_record
	
	spf=$(host -t txt $domain | grep -i "spf" | awk -F 'text' '{print $2}')
	spf_value=($(echo $spf | grep -oE " .all| redirect"))

	if [ "$spf" != "" ]; then	
		echo $spf
		
		while read line
		do
			unset spf_file_value1
			unset spf_file_value2
			unset spf_file_value3
			unset spf_file_value4
			unset spf_file_value5
			unset spf_grep
			unset spf_record

			spf_file_value1=$(echo "$line" | awk -F '::' '{print $1}')
			spf_file_value2=$(echo "$line" | awk -F '::' '{print $2}')
			spf_file_value3=$(echo "$line" | awk -F '::' '{print $3}')
			spf_file_value4=$(echo "$line" | awk -F '::' '{print $4}')
			spf_file_value5=$(echo "$line" | awk -F '::' '{print $5}')
			
			if [ "$spf_value" != "" ]; then
				spf_record=$(echo $spf | awk -F '"' '{print $2}' | awk -F "$spf_file_value1" '{print $1}')
			else
				spf_record=$(echo $spf | awk -F '"' '{print $2}')
			fi
			
			case $spf_value in
				"$spf_file_value1")
					echo ""
					if [ "$spf_file_value2" == "green" ]; then
						echo -e "${gON}$spf_file_value3${cOFF}"
					elif [ "$spf_file_value2" == "yellow" ]; then
						echo -e "${yON}$spf_file_value3${cOFF}"
					elif [ "$spf_file_value2" == "red" ]; then
						echo -e "${rON}$spf_file_value3${cOFF}"
					elif [ "$spf_file_value2" == "" ]; then
						echo $spf_file_value3
					fi

					if [ "$spf_file_value4" != "" -a "$spf_file_value5" != "" ]; then
						echo Proposal hardfail: '"'$spf_record -all'"'
						echo Proposal softfail: '"'$spf_record ~all'"'
					elif [ "$spf_file_value4" != "" -a "$spf_file_value5" == "" ]; then
						echo Proposal softfail: '"'$spf_record -all'"'
					fi
					;;
				redirect)
					spf_redirect=($(echo $spf | awk -F "redirect=" '{print $2}' | cut -d '"' -f1))
					spf_redirect_check=$(host -t txt $spf_redirect | grep -i "spf")
					spf_redirect_value=($(echo $spf_redirect_check | grep -oE " .all| redirect"))
					
					if [ "$spf_redirect_check" != "" ]; then
						case $spf_redirect_value in
							"$spf_file_value1")
								echo "SPF redirected to:"
								echo $spf_redirect_check
								echo ""
								if [ "$spf_file_value2" == "green" ]; then
									echo -e "${gON}$spf_file_value3${cOFF}"
								elif [ "$spf_file_value2" == "yellow" ]; then
									echo -e "${yON}$spf_file_value3${cOFF}"
								elif [ "$spf_file_value2" == "red" ]; then
									echo -e "${rON}$spf_file_value3${cOFF}"
								elif [ "$spf_file_value2" == "" ]; then
									echo $spf_file_value3
								fi

								if [ "$spf_file_value4" != "" -a "$spf_file_value5" != "" ]; then
									echo Proposal hardfail: '"'$spf_record -all'"'
									echo Proposal softfail: '"'$spf_record ~all'"'
								elif [ "$spf_file_value4" != "" -a "$spf_file_value5" == "" ]; then
									echo Proposal softfail: '"'$spf_record -all'"'
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

######################################

################ DMARC KI Version #################
funcDMARCcheck() {
	local dmarc
	
	dmarc=$(dig +noall +answer -t txt _dmarc.$domain)
	if [ -z "${dmarc}" ]; then
    		echo -e "${yON}DMARC not set!${cOFF}"
	else
    		echo -e "${gON}DMARC is set:${cOFF}" 
		echo ${dmarc}
	fi
	
	echo ""
	echo "Details: https://en.wikipedia.org/wiki/DMARC"
	echo ""
}

################ DNSSEC KI Version #################
funcDNSSECcheck() {
	local dnssec
	
	dnssec=$(dig +noall +answer +dnssec $domain | grep -i "RRSIG")
	if [ -z "${dnssec}" ]; then
    		echo -e "${yON}DNSSEC not set!${cOFF}"
	else
    		echo -e "${gON}DNSSEC is set:${cOFF}" 
		echo ${dnssec}
	fi
	
	echo ""
	echo "Details: https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions"
	echo ""
}

################ CAA KI Version #################
funcCAAcheck() {
	local caa
	
	caa=$(dig +noall +answer -t caa $domain)
	if [ -z "${caa}" ]; then
    		echo -e "${yON}CAA not set!${cOFF}"
	else
    		echo -e "${gON}CAA is set:${cOFF}" 
		echo ${caa}
	fi
	
	echo ""
	echo "Details: https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization"
	echo ""
}

############ BLACKLIST-CHECK ############
#Thanks to Agarzon, Quick Blacklist Check inspired by https://gist.github.com/agarzon/5554490
mailserver_blcheck() {
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
				echo -e "${gON}${list:-OK}${cOFF}"
			else
				bl_listed+=("${ip_listed[$i]}:$bl")
				echo -e "${rON}listed: ${list:----}${cOFF}"
			fi
		done
		echo ""
	done
}
###################################


host_blcheck() {
#Thanks to Agarzon, Quick Blacklist Check inspired by https://gist.github.com/agarzon/5554490
	local i
	local blacklists=$(<./inputs/project/bl/blacklists.txt)
	
	for ((i=0;i<${#arecord[*]};i++))
	do
		echo ${arecord[$i]}
		reverse_ip=$(echo ${arecord[$i]} \
			| sed -ne "s~^\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)$~\4.\3.\2.\1~p")
		reverse_dns=$(dig +short -x ${arecord[$i]})
		if [[ "${arecord[$i]}" != "alias" ]]; then
			echo IP ${arecord[$i]} HOST ${reverse_dns:----}
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
		echo ""
	done
}
#####################################

############### MAIL-HARVESTER ###############
#Thanks to TheHarvester - https://github.com/laramies/theHarvester
harvester_osint() {
	#mail_checked = global variable
	#mail_num = global variable
	local i
	local mail_addr

	mail_addr=($(theharvester -d $domain -l 200 -b google \
		| grep @ \
		| grep $domain))
	
	echo "----------------------"
	
	if [ "${mail_addr[*]}" != "" ]; then
		for ((i=0;i<${#mail_addr[*]};i++))
		do 
			mail_checked+=($(echo ${mail_addr[$i]} | grep "[\.@]$domain"))
		done
	fi

	mail_num=$(echo ${mail_checked[*]} | wc -w)
	
	if [ "${mail_checked[*]}" != "" ]; then
		if [ "${mail_checked[1]}" == "" ]; then
			echo -e "${yON}$mail_num Email address found!${cOFF}"
		else
			echo -e "${yON}$mail_num Email address found!${cOFF}"
		fi

		for ((i=0;i<${#mail_checked[*]};i++))
		do 
			echo  ${mail_checked[$i]}
		done	
		
	else
		echo -e "${gON}No email address found.${cOFF}"
	fi
	
	echo "----------------------"
	echo ""
}
###########################################

################### PWNED-CHECK ####################
#Thanks to Navan Chauhan for the code inspiration. - https://github.com/navanchauhan/Pwned
pwned_check() {
	local pwned
	local pasted
	local pastedid
	local i
	
	if [ "${mail_checked[*]}" == "" ]; then
	
		echo -e "${gON}No email address available to check.${cOFF}"
	else
		for ((i=0;i<${#mail_checked[*]};i++)); do 
			echo "Check ${mail_checked[$i]}:"
			pwned=$(wget -q -O- https://haveibeenpwned.com/api/v2/breachedaccount/${mail_checked[$i]} | jq '.[]' | jq '.Title')
			pasted=$(wget -q -O- https://haveibeenpwned.com/api/v2/pasteaccount/${mail_checked[$i]} | jq '.[]' | jq '.Source')
			pastedid=$(wget -q -O- https://haveibeenpwned.com/api/v2/pasteaccount/${mail_checked[$i]} | jq '.[]' | jq '.Id')
	
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

#########################################

################### SHODAN.IO-API #####################
shodan_check() {	
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
#################################################

################# MAILSERVER REDUNDANZ CHECK ###############
mail_redundanz() {
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

mail_loadbalance() {
	local mx_mail
	local mail2
	local mail3
	local mail4
	local check1
	local check2
	local check3
	
	mx_mail=($(host -t mx $domain | sort -V | cut -d " " -f7))
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

############ MAILSERVER STANDORT - DATENSCHUTZ ############
server_location() {
	local tld
	local geotld
	local geoCheck
	local i

	tld=$(echo $domain | sed -e 's/^.*\.//' | tr [:lower:] [:upper:])
	geotld=($(for((i=0;i<${#mailserver_ipv4[*]};i++));do geoiplookup ${mailserver_ipv4[$i]} | grep "GeoIP Country Edition:" | cut -d "," -f1 | cut -d " " -f4; done))

	geoCheck="$(echo ${geotld[*]} | sed -e "s/$tld//g" | sed 's/^[ \t]*//')"

	if [ "${geoCheck[*]}" == "" ]; then
		echo -e "${gON}*Mail server location in the same country as the domain extension.*${cOFF} [$tld]"
	else
		echo -e "${yON}*Mail server location may not be in the same country as the domain extension.*${cOFF} [$tld]"
	fi

	echo "Check the locations of the mail servers here (MX GEO-IP country code):" "["${geotld[*]}"]"
}
############################################################

blacklist_check() {
echo "IP-Blacklist Check - SPAM/Malware:"
if  [ "$bl_listed" == "" ];then
echo -e "${gON}*Not listed on any blacklist.*${cOFF}"
else
echo -e "${rON}*Blacklisted!*${cOFF}"
echo "Listed here (Host:Blacklist):"
for ((i=0;i<${#blListed[*]};i++))
	do 
		echo  ${bl_listed[$i]}
	done
fi
echo ""
if [ "$mailOsint" == "y" ];then
	echo "E-MAIL OSINT:"
	if [ "${mail_checked[*]}" != "" ]; then
		if [ "${mail_checked[1]}" == "" ]; then
			echo -e "${yON}$mail_num Email address found. Check details above.${cOFF}"
			echo ${mail_pwned[*]}
		fi
	else
		echo -e "${gON}No email address found.${cOFF}"
	fi
echo ""
fi
}

unset domain
unset mail
unset mail2
unset mail3
unset mail4
unset mailCheckIPv4
unset mail3CheckIPv4
unset mail4CheckIPv4
unset spf
unset spf_value
unset tld
unset geotld
unset geoCheck
unset geoCheck2
unset geoIPListed
unset testGeoIP
unset mailOnline
unset blacklists
unset blListed
unset checked
unset testIP
unset reverseIP
unset reverseDNS
unset list
unset mail_checked
unset mail_addr
unset mail_num

##################### END #####################