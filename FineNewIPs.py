'''
Language & Version:  Python 3.4
This script will allow you to identify a set of known IPs, then parse a directory with CSV/TXT files
look inside those files for IP addresses and compare them to the set you already have.

It then kicks out two files for you, one of any distinct new IP's (i.e. they weren't in your source file)
And a set of duplicate IP's, ones that you already have.

For the script to work please ensure the following.  Files are
1. CSV or TXT files only
1. The SOURCE (input1) file with the known IPs contains ONLY IPs
2. The FILES GETTING REVIEWED are
    a. Comma delimited 
    b. Have the IP address in the first column (other columns are ignored)
'''


import csv
import sys
import os
import os.path

def csv_itemgetter(index, delim):
    def composite(row):
        try:
            return row.split(delim)[index]
        except IndexError:
            return default
    return composite

print("For the script to work please ensure the files are:\n1. CSV or TXT files only\n1. The SOURCE (input1) file with the known IPs contains ONLY IPs\n2. The FILES GETTING REVIEWED are\n    a. Comma delimited \n    b. Have the IP address in the first column (other columns are ignored)")

new_info_source_path = str(input("\n\nWhat is the *PATH ONLY* to the directory that has the CSV or TXT files you want to search in?: "))
file_name_list = os.listdir(new_info_source_path)
lst_file_name_w_path = list()

for i in range(len(file_name_list)):
    filename = os.path.join(new_info_source_path,file_name_list[i] )
    lst_file_name_w_path.append(filename)


#Get the file that has the IP adresses we already know
known_info_source_path = str(input("\nWhat is the *PATH ONLY* to file with the known IPs: "))
known_info_file_name = str(input("\nWhat is the file name (include the extension): "))
known_info_filename_w_path = os.path.join(known_info_source_path,known_info_file_name)

#create the output files and enter the descriptions of the content
new_IPs_found = os.path.join(new_info_source_path,"new_distinct_ips_found.csv")#outputfile
with open (new_IPs_found,"w") as f:
    f.write("This file contains only the unique IPs that were found that you did not already have.\n")
    
dup_IPs_found = os.path.join(new_info_source_path,"dup_ips_found.csv")#outputfile
with open (dup_IPs_found,"w") as f:
    f.write("This file contains the IP addresses that were in your source document that also appeared in one or more of the files in the directory you specificed.\n")

new_all_IPs_found = os.path.join(new_info_source_path,"new_all_ips_found.txt")#outputfile
with open (new_all_IPs_found,"w") as f:
    f.write("This file contains the IP addresses that were NOT in your source document and appeared in one or more documents in the directory you specified.\nIf you want the full list WITHOUT duplicates review "+new_IPs_found+"\n")

#read in the IP column from all the source files into one temp file
for i in range(len(lst_file_name_w_path)):
    nextfile = lst_file_name_w_path[i]
    with open(str(nextfile),"r") as infile_newdata, open (new_all_IPs_found,"a") as outfile:
        reader = csv.reader(infile_newdata, delimiter =",")
        data = list(reader)
        for i in range(len(data)):
            ip = str(data[i][0]).strip(" \n\t\r abcdefghijklmnopqrstuvwxyz")#the first column is the ip address get rid of any spaces, tabs, new line characters or hard returns on both sides
            print(ip)
            if len(ip)>1:
                outfile.write(str(ip)+"\n")

'''
Keep the file that has ALL the IPs in it, even the duplicated ones in case someone needs to know how many times an IP address appeared
Also create a file of just the unique IP's
'''

#remove the duplicate IP address from the new data set
with open(new_all_IPs_found,'r') as in_file, open("temp_unique_ips.txt",'w') as out_file:
    seen = set() # set for fast O(1) amortized lookup
    for line in in_file:
        if line in seen: continue # skip duplicate
        seen.add(line)
        out_file.write(line)

'''
Finally, I have another list of historical IP's
1.  Create a list showing the dups, i.e. the ones that we have seen again
2.  Create a list showing any new IPs that aren't in our historical list
'''


#Look up the IPs in the new data file to see if they are in the list of known IPs
with open(known_info_filename_w_path, "r") as f1:
    s1 = set(x.strip() for x in f1)
with open("temp_unique_ips.txt", "r") as in_file, open(dup_IPs_found,"w") as out_file:
    out_file.writelines(x for x in in_file if x.strip() in s1)

with open(known_info_filename_w_path, "r") as f1:
    s1 = set(x.strip() for x in f1)
with open("temp_unique_ips.txt", "r") as in_file, open(new_IPs_found,"w") as out_file:
    out_file.writelines(x for x in in_file if x.strip() not in s1)


print("Your files are here: "+new_info_source_path)
