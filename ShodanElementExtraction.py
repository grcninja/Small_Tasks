#Python3.4
#Author - Tazz
'''
Thi script was written because we have a tendency to dump JSON data into TX files so multiple teams can have a copy.
We would normally run the ShodanBulkHost script first, which looks up a large list of IPs, then use this script.
This script allows the teams to pull out what fields matter to them, such as all the domain names that were in the file
 or all of the MAC addresses, timestamps, ip's etc....and put them all in one file.
I do not recommend using this if you want to pull groups of data such as all the location data elements.

It is worth noting, that the output isn't gorgeous, but with a few editing sweeps with Notepad++ it's perfect
I can't please everyone all the time. :)

go to https://developer.shodan.io/api/banner-specification for a list of data elements in the banners
'''

import datetime
import os
import os.path
import pprint
import shodan
import string
import sys
dt = datetime.date.today()
work = "Y"

def cleaner(name, custom=False): #False gets rid of all special characters
    illegal = ("!","@","#","$","%","^","&","*","(",")","{","}","[","]",":",";","'","<",">",",",".","?","/","|","'\'","~","`","+","=","\n","\t","\r")
    c_illegal = ("!","@","#","$","%","^","&","*","(",")","{","}","[","]",";","'","<",">",",","?","|","'\'","~","`","+","=","\n","\t","\r")
    cleaned = name
    i=0
    if custom == False:
        while i < len(illegal):
            cleaned = cleaned.replace(illegal[i],"")
            i+=1
    else:#custom is true, then periods(.), colons(:), forward slash (/) are allowed, note dashes are allowed by default
        while i < len(c_illegal):
            cleaned = cleaned.replace(c_illegal[i],"")
            i+=1
        if cleaned.find("ip_str"):
            cleaned = cleaned.replace(":","")
    cleaned.strip()
    return cleaned

def newfile(new_file_name, destination):
    file_name = cleaner(new_file_name, custom=False)
    output_file_name = (file_name+".txt")
    txt_output_full_file_name = os.path.join(destination, output_file_name)
    return txt_output_full_file_name

def extract_elements(input_file, output_file, field):
    special_string=False
    if field.find("ip_str"):special_string=True
    if field.find("timestamp"):special_string=True
    with open(input_file,'r') as in_file, open(output_file,'w') as out_file:
        seen = set()
        out_file.write("These are the "+field+" field entries.\n")
        for line in in_file:
            if line in seen: continue #skip duplicates
            if ("'"+field) in line:#the field port, is also found in support, so we add the apostrophes to match the exact field syntax
                seen.add(line)
                fline = cleaner(line, custom=special_string)
                fline = fline.replace(field,"")
                fline.strip()
                if len(fline)>0: #don't write blank lines, some of the raw data doesn't have data for some fields, but writes the blanks anyway
                    out_file.write(fline)
                    out_file.write("\n")

api = shodan.Shodan("YOUR API KEY HERE") #this wass Tazz's personal API key
print("This script will parse through a JSON source that was printed using ppprint.  It extracts the data in the line and creates a file with just those elements")

#Get User Input and set up the files to be written
input_path = str(input("Enter the *PATH ONLY* to the source file you want to search: "))
input_path = input_path.replace("/","'\'") #make sure they didn't copy the path from somewhere that used the wrong slashes
input_file_name = str(input("Enter the name of the file containing the data (include the extension): "))
txt_input_full_file_name = os.path.join(input_path, input_file_name)

#Get Output Destination
output_path = str(input("Enter the *PATH ONLY* where you want to save the file: "))
output_path = output_path.replace("/","'\'") #make sure they didn't copy the path from somewhere that used the wrong slashes

while work == "Y":
      field = str(input("What field do you want to search for (ex:domains)? "))
      field = cleaner(field, custom=False)
      output_fname = newfile(field, output_path)
      txt_output_full_file_name = os.path.join(output_path, output_fname)
      extract_elements(txt_input_full_file_name, txt_output_full_file_name, field)
      work  = str(input("Would you like to extract another data element from your source? (enter Y - anything else terminates the program) ")).upper().strip()


