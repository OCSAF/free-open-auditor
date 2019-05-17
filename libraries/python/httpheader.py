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

    #url = input("URL eingeben / z.B. http://www.test.ch: ")
    req = urllib.request.Request(
            url,
            data=None,
            headers=agent
            )
    http = urllib.request.urlopen(req)

   # print()
   # print("HTTP-Header for {}:".format(args["url"]))
   # print()
    print(http.headers)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True,
            help="Full URL - http://www.freecybersecurity.org")
    args = vars(parser.parse_args())
    funcHTTPHeader(args["url"])

############# END #############