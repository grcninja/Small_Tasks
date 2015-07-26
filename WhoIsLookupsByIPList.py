'''
Language & Version:  Python 3.4
This script allow the user to identify the path and file that holds a list of IP addresses
that they would like to loo up the domain name for.
The user can also indicate where to save the file and what to name it.

PRE-REQUSITES:
Download
1.  Get the stable relase of dnspython from here http://www.dnspython.org/
2.  Get the latest version of whoisip go here https://pypi.python.org/pypi
    and search for ipwhois in the search box.
Install
3.  After installing these, use pip3.4 to install the packages. 
'''
import csv
import datetime
import os
import os.path
import pprint
import socket
import urllib.request
from ipwhois import IPWhois


def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

print("THIS SCRIPT IS DESIGNED TO INGEST A LIST OF IP ADDRESSES ONLY.\n THE ONLY FORMATTING IT WILL DO FOR YOU IS REMOVE BLANK LINES OR WHITESPACE.\n**IF YOUR FILE HAS OTHER CRAP IN IT, THIS WON'T WORK.**\n\n")

input_path = str(input("Enter the *PATH ONLY* to the list of IPs is at that you want to look up: "))
input_name = str(input("Enter the name of the file containing the IPs (include the extension): "))
output_path = str(input("Enter the *PATH ONLY* to where you want to save your file: "))
output_name = str(input("What do you want to name YOUR file? (A date will be added automatically and it will get a .txt extension) "))
dt = datetime.date.today()
output_name = (output_name+"_"+str(dt)+".txt")
output_file_name = os.path.join(output_path, output_name)
input_file_name = os.path.join(input_path, input_name)
process_file_name = os.path.join(input_path, "cleaned_input.txt")

#stripout blank lines from the source file
with open(input_file_name,'r') as f, open(process_file_name,"w")as f2:
    for line in f:
        line.strip()
        f2.write(line)

lines = file_len(process_file_name)

with open(process_file_name,"r") as fin, open(output_file_name,"a") as fout:
    reader = csv.reader(fin)#pulling the domain name out of this to look up the IP
    d = list(reader)
    print("\n\n You will see the text 'Script Complete' when the results are ready.\n\n")
    for i in range(lines):
        ip = d[i][0]
        ip_lookup = ip.rstrip()
        obj = IPWhois(ip_lookup)
        results = obj.lookup()#this gives you back basics
        #results = obj.lookup(get_referral=True)  #this will give you referral WHOIS informatio if it is available
        #results = obj.lookup(inc_raw=True,get_referral=True)#inc_raw will give you exactly what is on the website, it will be a lot of extra detail
        results["nets"][0]['country']
        results["nets"][0]['abuse_emails']
        fout.write("\n\nRESULT_RECORD\n\n")
        pprint.pprint(results, fout)#writes the results in an easy to read format


print("Script Complete")
           
