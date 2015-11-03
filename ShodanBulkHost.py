#Python3.4
#Author - Tazz
'''
This script parses through a list of IP's, looks them up on Shodan.
Then it writes one large file with the results including the history,
  and it writes a separate results file for each IP address.
To avoid getting the full history of the IP you simply need to remove history=True as the default is False
'''

import datetime
import os
import os.path
import pprint
import shodan
import string
import sys
dt = datetime.date.today()


def newfile(new_file_name, destination):
    fname = new_file_name.replace(".","_").strip("\n")
    output_file_name = (new_file_name+".txt")
    txt_output_full_file_name = os.path.join(destination, output_file_name)
    return txt_output_full_file_name

api = shodan.Shodan("YOUR API KEY HERE") #this was Tazz's personal API key
print("THIS SCRIPT IS DESIGNED TO INGEST A LIST OF IP ADDRESSES ONLY.\n THE ONLY FORMATTING IT WILL DO FOR YOU IS REMOVE BLANK LINES OR WHITESPACE.\n**IF YOUR FILE HAS OTHER CRAP IN IT, THIS WON'T WORK.**\n\n")

#Get User Input and set up the files to be written
input_path = str(input("Enter the *PATH ONLY* to the list of IPs is at that you want to look up: "))
input_file_name = str(input("Enter the name of the file containing the IPs (include the extension): "))
txt_input_full_file_name = os.path.join(input_path, input_file_name)

#Get Output Destination
output_path = str(input("Enter the *PATH ONLY* where you want to save the file: "))
output_path = output_path.replace("/","'\'") #make sure they didn't copy the path from somewhere that used the wrong slashes

#Create Output File for the full set of results, to be in one single file
txt_JSON_file_name = ("ShodanHostResults_"+str(dt)+".txt")
txt_JSON_full_file_name = os.path.join(output_path, txt_JSON_file_name)


with open(txt_input_full_file_name,"r") as input_file, open(txt_JSON_full_file_name,"a") as JSON_output:
    for line in input_file:
        node = line.strip()
        #look up IP on Shodan and print to the master file
        try:
            host = api.host(node, history=True) #for the most recent results only, change this to False
            try:
                pprint.pprint(host, JSON_output)
            except: continue
                '''
                This is a cheap fast way to get around handling this error:
                UnicodeEncodeError: 'charmap' codec can't encode character '\ufffd' in position 9: character maps to <undefined>
                which is thrown for a reason that I don't have time to dig into right now.
                '''
            #make a separate file to hold just the one IP's information, unique with the IP in the title
            fname = newfile(node, output_path)
            with open(fname, "w") as output_file:
                output_file.write("Shodan Reults for "+node+"\n")
                pprint.pprint(host, output_file)
        except shodan.exception.APIError as err:
            JSON_output.write("\nNo Information for "+node+"\n")
            name = node+"_NoResults"
            fname = newfile(name, output_path)
            with open(fname, "w") as output_file:
                output_file.write("There are No Shodan Reults for "+node+"\n")

