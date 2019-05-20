#!/usr/bin/python3

#######################################################################
################### FREE OCSAF HTTP Header FUNCTION ###################
#######################################################################

################################################################################################
#  FROM THE FREECYBERSECURITY.ORG TESTING-PROJECT (GNU-GPLv3) - https://freecybersecurity.org  #
#  With this script the HTTP Header can be fetched.                                            #
#                                                                                              #
#  Use only with legal authorization and at your own risk! ANY LIABILITY WILL BE REJECTED!     #
#                                                                                              #
#  Script programming by Mathias Gut, Netchange Informatik GmbH under GNU-GPLv3                #
#  Special thanks to the community and also for your personal project support.                 #
################################################################################################


############## Libraries ###############

import urllib.request
import argparse


############# HTTP Header ##############

def funcHTTPHeader(url):
    
    agent = { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:62.0) Gecko/20100101 Firefox/62.0' }
    #agent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'}

    req = urllib.request.Request(
            url,
            data=None,
            headers=agent
            )
    try:http = urllib.request.urlopen(req)
    except urllib.error.URLError as err:
        print("ERROR: {} {}".format(err.code,err.reason))

    print(http.headers)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True,
            help="Full URL - http://www.freecybersecurity.org")
    args = vars(parser.parse_args())
    url = args["url"]
    funcHTTPHeader(url)

############# END #############