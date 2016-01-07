#Author: Tazz
#Python 3.5
#This script is designed to allow the user to input one IP and see the output on the screen

import shodan
import pprint

api = shodan.Shodan("YOUR API KEY HERE")

ip = str(input("What IP do you want to look up?:  "))
host = api.host(ip, history=True)
pprint.pprint(host)
