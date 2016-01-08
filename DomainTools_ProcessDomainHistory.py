#Author Tazz
#Python 3.5

import csv
import datetime
import os
import socket

#used for file names
dt = datetime.date.today()
dstr = dt.strftime("%Y%m%d")
dtm = datetime.datetime.now()
dtmstr = dstr+"_"+dtm.strftime("%H%M")
tm_HHmm = dtm.strftime("%H%M")

def checkfordir_byfile(fil3):
    directory = os.path.dirname(fil3)
    if not os.path.exists(directory):
    	os.makedirs(directory)

def checkfordir_bydirectory(dir3ctory):
	directory = dir3ctory
	if not os.path.exists(directory):
		os.makedirs(directory)

def clean(filename):
	illegal = ("!","@","#","$","%","^","&","*","(",")","{","}","[","]",":",";","'","<",">",",",".","?","/","|","'\'","~","`","+","="," ","\n","\t","\r")
	cleaned = filename.strip()
	for i in range(len(illegal)):
		cleaned = cleaned.replace(illegal[i],"_")
	return cleaned

def get_field_from_csv(csvfile, outfile, field, uniq=True):
	with open(csvfile, "r") as fin, open(outfile, "w") as fout:
		reader = csv.DictReader(fin)
		unique =  uniq
		seen = set() 
		find = field
		print("Creating a file of all the "+find+"...")
		for row in reader:
			found = row[find]
			if unique:
				if found in seen: continue 
			seen.add(found)
			fout.write(found+"\n")


#Get something to append to the file names to make them unique and relevant
targetname = clean(str(input("A single word to add to the end of all the files, a target name perhaps?: ")))
pathout = str(input("where should the files be written to?: "))
new_folder = dtmstr+"_"+targetname
dirout = os.path.join(pathout,new_folder)
checkfordir_bydirectory(dirout)

#Parse the Domain Tools dump, extract the unique domains to a file
domains_all = os.path.join(dirout,"domains_all_"+targetname+".txt")
domaintools_history = str(input("Enter the full path and full filename of the domain tools dump, it should start with RWR_ and end in .csv: "))
dthistory_filename = os.path.basename(domaintools_history)

with open(domaintools_history, "r") as fin, open(domains_all, "w") as fout:
	reader = csv.DictReader(fin)
	seen = set() 
	print("Creating a file of unique domains...")
	for row in reader:
		found = row['Domain']
		if found in seen: continue 
		seen.add(found)
		fout.write(found+"\n")

'''
Take that list of domains, and let's create some files we'll need:
1.  One listing the unique IPs addresses
2.  One with the domain name and corresponding IP
3.  One with the domain name, corresponding IP, and the target's name 
4.  One listing just the domains that have an IP, the live domains
'''

IPs_unique = os.path.join(dirout,"IPs_unique_all_"+targetname+".txt")
domain_ip_results = os.path.join(dirout,"domain_ip_results_"+targetname+".csv")
domains_live = os.path.join(dirout,"domains_live_"+targetname+".txt")
targetsdomains = os.path.join(dirout,"domains2ip_"+targetname+".csv")

seen_ips = set()
with open(domains_all,"r") as fin, open(IPs_unique,"w") as ipslive, open(domain_ip_results, "w") as domain2ip, open(domains_live,"w") as domainslive, open(targetsdomains,"w") as targetslivedomains:
	for line in fin:
		check_domain = str(line.strip("\n"))
		try:
			result = socket.getaddrinfo(check_domain, 80, proto=socket.IPPROTO_TCP)
			#getaddrinfo returns a list of 5-tuples with the following structure(family, type, proto, canonname, sockaddr)
			entry = result.pop(0) 
			for i, x in enumerate(entry):
				if i == 4: #this is the sockaddr, it's a tuple with a result like ('123.456.789.123', 80)
					ip = x
					for z, y in enumerate(ip):
						if z == 0: #there are always 2 results, we only need the IP one time
							ipaddy = str(ip[0])
							domainslive.write(check_domain+"\n")
							domain2ip.write(check_domain+","+ipaddy+"\n")
							targetslivedomains.write(check_domain+","+ipaddy+","+targetname+"\n")
							if ipaddy in seen_ips: continue
							seen_ips.add(ipaddy)
							#ipslive.write(ipaddy+"\n")
		except: continue #some of the domains might not be live, and will throw errors

sortedIPs = sorted(seen_ips)
with open(IPs_unique,"w") as f:
	for x in range(len(sortedIPs)):
		f.write(sortedIPs[x]+"\n")

#create the splunk queries
linecount = 0
with open(domains_live) as f:
	for line in f:
		linecount += 1
print("Line count "+str(linecount))

#recommend changing the search1 & search2 text to something relevant
splunk_search1 = os.path.join(dirout,"splunk_search1_"+targetname+".txt")
splunk_search2 = os.path.join(dirout,"splunk_search2_"+targetname+".txt")

index1 = some_splunk_index1
field1 = the_field_name_that_has_urls1
index2 = another_splunk_index1
field2 = the_field_name_that_has_urls2

with open(domains_live, "r") as fin, open(splunk_search1, "w") as fout_search1, open(splunk_search2, "w") as fout_search2:
	fout_search1.write('index="'+index1+ ' AND (')
	fout_search2.write('index="'+index2+ ' AND (')
	x = 0
	for line in fin:
		fline = line.strip("\n")
		fline1 = field1+"=*"+fline+"*"
		fline2 = field2+"=*"+fline+"*"
		if (x < (linecount-1)):
			fline1 = fline1+" OR "
			fline2 = fline2+" OR "
			fout_search1.write(fline1)
			fout_search2.write(fline2)
			x += 1
		else:
			fline1 = fline1+")"
			fline2 = fline2+")"
			fout_search1.write(fline1)
			fout_search2.write(fline2)


