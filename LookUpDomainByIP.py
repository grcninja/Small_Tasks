'''
Language & Version:  Python 3.4
This script allow the user to identify the path and file that holds a list of IP addresses
that they would like to look up the domain name for.
The user can also indicate where to save the file and what to name it.
'''

import csv
import datetime
import fileinput
import os
import socket
import sys

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
        line.rstrip()
        f2.write(line)

lines = file_len(process_file_name)

with open(process_file_name,"r") as fin, open(output_file_name,"w") as fout:
    reader = csv.reader(fin)#pulling the domain name out of this to look up the IP
    d = list(reader)
    print(d)
    print("lines = "+str(lines))
    for i in range(lines):
        print("Loop number "+str(i))
        ip = d[i][0]
        print("looking up "+str(ip))
        try:
            domain = socket.gethostbyaddr(ip)
            print(str(domain))
            fout.write(str(domain)+","+str(ip)+"\n")
        except socket.herror as e:
            fout.write(str(e)+"'"+str(ip)+"\n")
        except socket.gaierror as e:
            fout.write(str(e)+"'"+str(ip)+"\n")   
        except socket.timeout as e:
            fout.write(str(e)+"'"+str(ip)+"\n")
           
