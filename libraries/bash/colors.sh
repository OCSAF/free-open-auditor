#!/bin/bash

#################################################################################
################### COLOR Library - under GPLv3               ###################
################### by Mathias Gut, Netchange Informatik GmbH ###################
################### From the freecybersecurity.org Project    ###################
################### Thanks to the community!                  ###################
#################################################################################

###############
### COLORS  ###
###############

#Import this as library with 
#. colors.sh or

if [[ $colors -eq 1 ]]; then
	cOFF=''

	blON=''
	rON=''
	gON=''
	yON=''
	bON=''
	mON=''
	cON=''
	lgrON=''

	dgON=''
	lrON=''
	lgON=''
	lyON=''
	lbON=''
	lmON=''	
	lcON=''	
	wON=''	
else
	cOFF='\e[39m'	#color OFF / Default color
	
	blON='\e[30m'	#black color ON
	rON='\e[31m'	#red color ON
	gON='\e[32m'	#green color ON
	yON='\e[33m'	#yellow color ON
	bON='\e[34m'	#blue color ON
	mON='\e[35m'	#magenta color ON
	cON='\e[36m'	#cyan color ON
	lgrON='\e[37m'	#light gray ON
	
	dgON='\e[90m'	#dark grey ON
	lrON='\e[91m'	#light red ON
	lgON='\e[92m'	#light green ON
	lyON='\e[93m'	#light yellow ON
	lbON='\e[94m'	#light blue ON
	lmON='\e[95m'	#light magenta ON
	lcON='\e[96m'	#light cyan ON
	wON='\e[97m'	#white color ON
fi

################### END ###################