#Python 3.4

import datetime
import os.path
import pprint
import shodan
import string
import sys

api = shodan.Shodan("API KEY HERE") #this was Tazz's personal API key
query = "product:*trojan*"
results = api.search(query, minify=False)

#Get User Input
save_path = str(input("Enter the path where you want to save the file: "))
save_path = save_path.replace("/","'\'") #make sure they didn't copy the path from somewhere that used the wrong slashes
dt = datetime.date.today()
txt_file_name = ("ShodanResults_"+str(dt)+".txt")
ip_file_name = ("trojanIPs_"+str(dt)+".txt")
domain_file_name = ("trojanDomains_"+str(dt)+".txt")
temp_file_name = ("temp.txt")
txt_full_file_name = os.path.join(save_path, txt_file_name)
ip_full_file_name = os.path.join(save_path, ip_file_name)
domain_full_file_name = os.path.join(save_path, domain_file_name)

#raw output in display
#pprint.pprint(results)

#write the complete raw output to a file, in an easy to read format
with open(txt_full_file_name,'w') as fout:
    pprint.pprint(results, fout)

#create a file with ONLY IP addresses  
with open(txt_full_file_name,'r') as in_file, open(ip_full_file_name ,'w') as out_file_ip:
    seen = set()
    for line in in_file:
        if line in seen: continue #skip duplicates
        if "'ip_str'" in line:
            seen.add(line)
            fline = line.strip().replace("'ip_str': '", "").replace("',", "") #thx @loji
            out_file_ip.write(fline)
            out_file_ip.write("\n")

#create a file with ONLY domains  
with open(txt_full_file_name,'r') as in_file, open(domain_full_file_name,'w') as out_file_domains:
    seen = set()
    for line in in_file:
        if line in seen: continue #skip duplicates
        if "'domains'" in line:
            seen.add(line)
            fline = line.replace("'domains': ", "").replace("'", "").replace("[","").replace("],","").replace(",","").strip() #thx @loji
            if len(fline)>0: #don't write blank lines, some of the raw data doesn't have domain data, but writes the line anyway
                out_file_domains.write(fline)
                out_file_domains.write("\n")
