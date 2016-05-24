#!/usr/bin/python
'''
Python 3.5 compatible
This will create a comma delimited file
it requires you to have a GeoIP2-City database from MaxMind.
  https://www.maxmind.com/en/geoip2-databases
  https://www.maxmind.com/en/geolite2-developer-package

If you do not wish to purchase this you can comment out the GeoDB class
and use the ShodanNode class.  You will also need to remove the code for
any of the MaxMind variable and keys

You will also need to get a Shodan API Key which you can get with a free account.

A new section has been added to help the user check for and set up
a default file structure to run this script. Please review the section below commented with
#Check for necessary folders and files

Dependencies on:
* geoip2 2.3.0
* ipwhois3 0.13
* shodan 1.5.3
'''
import csv
import datetime
import geoip2.database
from ipwhois import IPWhois
import json
import os.path
import pprintpp as pp #used for troubleshooting type pp.pprint(stuff)
import requests
import shodan
import sys


class GeoDB(object):
    def __init__(self, maxmind_db_path):
        self.reader = geoip2.database.Reader(maxmind_db_path)
    def lookup_ip(self, ip_addr):
        geo_ip = {"MaxMind_ip_iso_code":"UNK","MaxMind_ip_country":"UNK","MaxMind_ip_state":"UNK","MaxMind_ip_city":"UNK","MaxMind_ip_zipcode":"UNK"}
        #open GeoIP2 data reader
        try:
            ip = self.reader.city(ip_addr)
            if ip.country.iso_code is not None:
                geo_ip["MaxMind_ip_iso_code"] = (newline_clean(ip.country.iso_code)) #US
            if ip.country.name is not None:
                geo_ip["MaxMind_ip_country"] = (newline_clean(ip.country.name)) #'United States'
            if ip.subdivisions.most_specific.name is not None:
                geo_ip["MaxMind_ip_state"] = (newline_clean(ip.subdivisions.most_specific.name)) #'Minnesota'
            if ip.city.name is not None:
                geo_ip["MaxMind_ip_city"] = (newline_clean(ip.city.name)) #'Minneapolis'
            if ip.postal.code is not None:
                geo_ip["MaxMind_ip_zipcode"] = (newline_clean(ip.postal.code)) #'55455'
        except:
            print("Error getting MaxMind Data")
        return geo_ip
    
class ShodanNode(object):
    def __init__(self):
        credentials = get_creds("shodan")
        api_key = credentials.pop("api_key")
        self.api = shodan.Shodan(api_key)
        credentials.clear()
    def get_shodan(self, ip_addr):
        hostnames = []
        domains = []
        ports = []
        seen_host = set()
        seen_domain = set()
        seen_port = set()
        sho = {"timestamp":"TBD",
               "os":"UNK",
               "product":"UNK",
               "isp":"UNK",
               "asn":"UNK",
               "org":"UNK",
               "hostnames":"UNK",
               "domains":"UNK",
               "ports" : "UNK",
               "loc_city":"UNK",
               "loc_region_code":"UNK",
               "loc_are_code":"UNK",
               "loc_longitude":"UNK",
               "loc_latitiude":"UNK",
               "loc_country_code_3": "UNK",
               "loc_country_code":"UNK",
               "loc_country_name":"UNK",
               "loc_postal_code":"UNK",
               "loc_dma_code":"UNK",}
        try:
            host = self.api.host(ip_addr)
            #pp.pprint(host)
            if host['ports'] is not None:
                if len(host['ports']) > 0:
                    for x in range(len(host['ports'])):
                        new_port = str(host['ports'][x])
                        if new_port in seen_port: continue
                        seen_port.add(new_port)
                        new_port = new_port + ";"
                        ports.append(new_port)
                        #pp.pprint(ports)
            if host['data'] is not None:
                for item in host['data']:      
                    if 'timestamp' in item and item['timestamp'] is not None:
                        sho["timestamp"] = item['timestamp']
                    if 'os' in item and item['os'] is not None:
                        sho["os"] = item['os']
                    if 'isp' in item and item['isp'] is not None:
                        sho["isp"] = item['isp']
                    if 'org' in item and item['org'] is not None:
                        sho["org"] = item['org']
                    if 'asn' in item and item['asn'] is not None:
                        sho["asn"] = item['asn']
                    if 'product' in item and item['product'] is not None:
                        sho["product"] = item['product']
                    if 'hostnames' in item and len(item['hostnames']) > 0:
                        for x in range(len(item['hostnames'])):
                            new_hostname = item['hostnames'][x]
                            if new_hostname in seen_host:continue
                            seen_host.add(new_hostname)
                            new_hostname = new_hostname + ";"
                            hostnames.append(new_hostname)
                            #pp.pprint(hostnames)
                    if 'domains' in item and len(item['domains']) > 0:
                        for x in range(len(item['domains'])):
                            new_domain = item['domains'][x]
                            if new_domain in seen_domain: continue
                            seen_domain.add(new_domain)
                            new_domain = new_domain + ";"
                            domains.append(new_domain)
                            #pp.pprint(domains)
                    if 'location' in item:
                        if item['location']['city'] is not None:
                            sho["loc_city"] = item['location']['city']
                        if item['location']['region_code'] is not None:
                            sho["loc_region_code"] = item['location']['region_code']
                        if item['location']['area_code'] is not None:
                            sho["loc_area_code"] = item['location']['area_code']
                        if item['location']['longitude'] is not None:
                            sho["loc_longitude"] = item['location']['longitude']
                        if item['location']['latitude'] is not None:
                            sho["loc_latitude"] = item['location']['latitude']
                        if item['location']['country_code3'] is not None:
                            sho["loc_country_code3"] = item['location']['country_code3']
                        if item['location']['country_code'] is not None:
                            sho["loc_country_code"] = item['location']['country_code']
                        if item['location']['country_name'] is not None:
                            sho["loc_country_name"] = item['location']['country_name']
                        if item['location']['postal_code'] is not None:
                            sho["loc_postal_code"] = item['location']['postal_code']
                        if item['location']['dma_code'] is not None:
                            sho["loc_dma_code"] = item['location']['dma_code']
                
                sho["hostnames"] = hostnames
                sho["domains"] = domains
                sho["ports"] = ports
        except:
            print("Error in ShodanNode")
        return sho

class Emails(object):
    '''
    Not all of the RIR's store contact info in the same ways at the same levels and an abuse email can be burried.
    After testing on 700 IPs from various RIRs showed that there is ABSOLUTELY NO consistency as to which level you
    find a true asbuse contact. So we are parsing multiple levels (depth=x) to get all the emails.
    In some test cases the first abuse email didn't appear until level 3
    '''
    def __init__(self, ip):
        self.WIobj = IPWhois(ip, timeout=20)
    def get_emails(self, max_depth):
        email_list = list()
        seen = set()
        try:
            for x in range(max_depth):
                results = self.WIobj.lookup_rdap(depth=x)
                for m in results['objects'].items():
                    if results['objects'] is not None:
                        for x in results['objects']:
                            tmp_em = results['objects'][x]['contact']['email']
                            if tmp_em is not None:
                                for y in range(len(tmp_em)):
                                    if tmp_em is not None:
                                        email = tmp_em[y]['value']
                                        if email in seen: continue
                                        seen.add(email)
                                        email_list.append(email)
                                        
        except:
            print("Error in the get_emails function")
        return email_list

def get_creds(source_name):
    creds = {"user":"" , "api_key":""}
    while source_name is not None:
        if source_name == "domain_tools":
            credfile = os.path.expanduser('~/api_creds/domaintools.dtapi.txt')
            with open(credfile,'r') as f:
                creds["user"] = f.readline().strip()
                creds["api_key"] = f.readline().strip()
                break
        if source_name == "shodan":
            credfile = os.path.expanduser('~/api_creds/shodan.txt')
            with open(credfile,'r') as f:
                creds["api_key"] = f.readline().strip()
                break
        if source_name == "virus_total":
            credfile = os.path.expanduser('~/api_creds/vt.txt')
            with open(credfile,'r') as f:
                creds["user"] = f.readline().strip()
                creds["api_key"] = f.readline().strip()
    return creds
    

def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

def newline_clean(original):
    try:
        cleaned = original.replace("\n","|").replace("\r","|").replace("\t","|")
    except:
         cleaned = original#shame on me for this
    return cleaned

def phone_clean(phone):
    try:
        just_phone = phone.strip("\n\r\t abcdefghijklmnopqrstuvwxyz:;")
    except:
        just_phone = phone
    return just_phone

def get_threatcrowd(ip):
    hashes = []
    seen_hash = set()
    references = []
    seen_ref = set()
    domain_resolutions = []
    
    tc = {"hashes":"UNK",
          "permalink":"UNK",
          "references":"UNK",
          "domain_resolutions":"UNK",
          "verdict_response_code":"UNK",}
    tc_result = json.loads(requests.get("http://www.threatcrowd.org/searchApi/v2/ip/report/", {"ip": ip}).text)
    if tc_result is not None:
        if 'hashes' in tc_result and len(tc_result['hashes']) > 0:
                for x in range(len(tc_result['hashes'])):
                    new_hash = tc_result['hashes'][x]
                    if new_hash in seen_hash:continue
                    seen_hash.add(new_hash)
                    new_hash = new_hash + ","
                    hashes.append(new_hash)
            
        if 'permalink' in tc_result and tc_result['permalink'] is not None:
            tc["permalink"] = tc_result['permalink']

        if 'references' in tc_result and len(tc_result['references']) > 0:
            for x in range(len(tc_result['references'])):
                new_ref = tc_result['references'][x]
                if new_ref in seen_ref:continue
                seen_ref.add(new_ref)
                new_ref = new_ref + ","
                references.append(new_ref)

        if 'resolutions' in tc_result and len(tc_result['resolutions']) > 0:
            for x in range(len(tc_result['resolutions'])):
                domain = newline_clean(tc_result['resolutions'][x]['domain'])
                resolved_date = tc_result['resolutions'][x]['last_resolved']
                entry = domain + ";" + resolved_date +","
                domain_resolutions.append(entry)

        if 'response_code' in tc_result:
            if 1 == int(tc_result['response_code']):
                tc["verdict_response_code"] = "not malicious"
            if 0 == int(tc_result['response_code']):
                tc["verdict_response_code"] = "neutral"
            if -1 == int(tc_result['response_code']):
                tc["verdict_response_code"] = "malicious"
                
                
        tc["hashes"] = hashes
        tc["references"] = references
        tc["domain_resolutions"] = domain_resolutions

    #pp.pprint(tc_result)
    return tc

dt = datetime.date.today()

#Check for necessary folders and files
input_file_path_and_name = ""
output_path = ""
maxmind_db_path = ""

missing_something = False

if os.path.isfile(os.path.expanduser('~/scripts/ip_hunter/inputs/ips.txt')):
    input_file_path_and_name = os.path.expanduser('~/scripts/ip_hunter/inputs/ips.txt')
else:
    print("missing the ips.txt file")
    missing_something = True

if os.path.lexists(os.path.expanduser('~/scripts/ip_hunter/configs/GeoIP2-City.mmdb')):
    maxmind_db_path = os.path.expanduser('~/scripts/ip_hunter/configs/GeoIP2-City.mmdb')
else:
    print("missing the GeoIP2-City.mmdb file")
    missing_something = True

if os.path.isdir(os.path.expanduser('~/scripts/ip_hunter/outputs')):
    output_path = os.path.expanduser('~/scripts/ip_hunter/outputs')
else:
    print("missing the outputs directory")
    missing_something = True

if missing_something:
    try:
        if not os.path.isdir(os.path.expanduser('~/scripts/ip_hunter/configs')):
            os.makedirs(os.path.expanduser('~/scripts/ip_hunter/configs'))
            with open(os.path.expanduser('~/scripts/ip_hunter/configs/readme.txt'),'a+') as config:
                config.seek(0)
                config.write("put your Maxmind_GeoIP2-City.mmdb in this directory")
    except e as FileExistsError:
        print("Cannot create the config directory because it already exists")
    try:
        if not os.path.isdir(os.path.expanduser('~/scripts/ip_hunter/inputs')):
            os.makedirs(os.path.expanduser('~/scripts/ip_hunter/inputs'))
            with open(os.path.expanduser('~/scripts/ip_hunter/inputs/readme.txt'),'a+') as config, \
                    open(os.path.expanduser('~/scripts/ip_hunter/inputs/ips.txt'),'a+') as ips:
                config.seek(0)
                ips.seek(0)
                config.write("This directory should have at minimum a text file named ips.txt with IP addresses, 1 per line.")
    except e as FileExistsError:
        print("Cannot create the inputs directory because it already exists")
        
    try:
        if not os.path.isdir(os.path.expanduser('~/scripts/ip_hunter/outputs')):
            os.makedirs(os.path.expanduser('~/scripts/ip_hunter/outputs'))
            with open(os.path.expanduser('~/scripts/ip_hunter/outputs/readme.txt'),'a+') as config:
                config.seek(0)
                config.write("This directory will hold output files from this script and any error log.")
    except e as FileExistsError:
        print("Cannot create the inputs directory because it already exists")
    print('''
    Your system was not set up with the directory structure and source files that this script expected.
    The directories have been created for you at ~/scripts/ip_hunter/.  
    Each directory has a readme describing the expected content.
    *  The configs directory - place ONLY ONE MaxMind GeoIP2-City.mmdb (with that name) in here
    *  The inputs directory should have at minimum ips.txt with ip addresses, 1 per line
    *  The outputs directory will hold the results of the script.

    Please andd the files above and restart the script to continue processing.''')
    sys.exit()
    
#output_path = str(input("Enter the path you want your output written to.\n Note your output file will be called IP_details_$date_.csv: "))
output_name = ("IP_Hunting_"+str(dt)+".csv")
output_file_name = os.path.join(output_path, output_name)
process_file_name = os.path.join(output_path,"cleaned_input.txt")
errors_file = os.path.join(output_path,"processing_errors.txt")

#sort file and stripout blank lines
with open(input_file_path_and_name,"r") as f, open(process_file_name,"w")as f2:
    seen = set()
    for line in f:
        ip = line.strip(" \n\t\r abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+`-={}|[]\\:;<>\/,")
        if ip in seen: continue
        f2.write(ip+"\n")
        seen.add(ip)


#General re-useable objects
geoip = GeoDB(maxmind_db_path)
showme = ShodanNode()

work = file_len(process_file_name)
print(str(work)+" ips to process\n")

with open(process_file_name,"r") as fin, open(output_file_name,"w",newline='',encoding="ascii", errors="ignore") as csvfile:

    #set up CSV file
    fieldnames = ["ip_addr" ,
                  "whois_abuse_email",
                  "whois_handle" ,
                  "whois_asn" ,
                  "whois_asn_country_code" ,
                  "whois_network_cidr" ,
                  "whois_contact_address" ,
                  "whois_contact_emails" ,
                  "whois_contact_phone" ,
                  "whois_contact_name" ,
                  "whois_contact_title" ,
                  "whois_contact_role" ,
                  "whois_contact_info_link1" ,
                  "whois_contact_info_link2" ,
                  "whois_contact_info_link3" ,
                  "MaxMind_ip_iso_code" ,
                  "MaxMind_ip_country" ,
                  "MaxMind_ip_state" ,
                  "MaxMind_ip_city" ,
                  "MaxMind_ip_zipcode",
                  "shodan_timestamp",
                  "shodan_os",
                  "shodan_product",
                  "shodan_isp",
                  "shodan_asn",
                  "shodan_org",
                  "shodan_hostnames",
                  "shodan_domains",
                  "shodan_ports",
                  "shodan_loc_city",
                  "shodan_loc_region_code",
                  "shodan_loc_are_code",
                  "shodan_loc_longitude",
                  "shodan_loc_latitiude",
                  "shodan_loc_country_code_3",
                  "shodan_loc_country_code",
                  "shodan_loc_country_name",
                  "shodan_loc_postal_code",
                  "shodan_loc_dma_code",
                  "threatcrowd_hashes",
                  "threatcrowd_permalink",
                  "threatcrowd_references",
                  "threatcrowd_domains_resolved_date",
                  "threatcrowd_verdict"]
    
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()


    
    for line in fin:
        addr = line.rstrip().strip()
        print("Processing {0}, {1} IPs remaining".format(addr,work-1))

        #set up Whois data variables
        whois_abuse_email = "None"
        whois_handle = "None" 
        whois_asn = "None"
        whois_asn_country_code = "None" 
        whois_network_cidr = "None" 
        whois_contact_address = "None" 
        whois_contact_phone = "None" 
        whois_contact_name = "None" 
        whois_contact_title = "None" 
        whois_contact_role = "None" 
        whois_contact_info_link1 = "None" 
        whois_contact_info_link2 = "None" 
        whois_contact_info_link3 = "None"
        contact_emails = list()

        #Get WhoIs Email Data
        try:
            max_depth = 5
            email_entries = Emails(addr)
            contact_emails = email_entries.get_emails(max_depth)
            whois_send_to = "none"
            if contact_emails is not None:
                whois_send_to = ""
                for a in range(len(contact_emails)):
                    entry = contact_emails[a]
                    if "abuse" in entry:
                        whois_abuse_email = entry
                    entry = entry + ";"
                    whois_send_to = whois_send_to + entry
                    
        except:
            print("Well this isn't working")

        #Get GeoIP data from MaxMind database
        geo_data = geoip.lookup_ip(addr)#returns a dictionary
        MaxMind_ip_iso_code = geo_data.pop("MaxMind_ip_iso_code")
        MaxMind_ip_country = geo_data.pop("MaxMind_ip_country")
        MaxMind_ip_state = geo_data.pop("MaxMind_ip_state")
        MaxMind_ip_city = geo_data.pop("MaxMind_ip_city")
        MaxMind_ip_zipcode = geo_data.pop("MaxMind_ip_zipcode")
        geo_data.clear() #for good measure

        #Get Shodan data
        shod = showme.get_shodan(addr) #returns dictionary
        shodan_timestamp = shod.pop("timestamp")
        shodan_os = shod.pop("os")
        shodan_product = shod.pop("product")
        shodan_isp = shod.pop("isp")
        shodan_asn = shod.pop("asn")
        shodan_org = shod.pop("org")

        namelist = shod.pop("hostnames")
        namestring = ""
        if len(namelist) == 0:
            namestring = "None found"
        for x in range(len(namelist)):
            name = namelist[x]
            namestring = namestring + name
        shodan_hostnames = namestring

        domainlist = shod.pop("domains")
        domainstring = ""
        if len(domainlist) == 0:
            domainstring = "None found"
        for x in range(len(domainlist)):
            name = domainlist[x]
            domainstring = domainstring + name
        shodan_domains = domainstring

        portlist = shod.pop("ports")
        portstring = ""
        if len(portlist) == 0:
            portstring = "None found"
        for x in range(len(portlist)):
            name = portlist[x]
            portstring = portstring + name
        shodan_ports = portstring
        
        shodan_loc_city = shod.pop("loc_city")
        shodan_loc_region_code = shod.pop("loc_region_code")
        shodan_loc_are_code = shod.pop("loc_are_code")
        shodan_loc_longitude = shod.pop("loc_longitude")
        shodan_loc_latitiude = shod.pop("loc_latitiude")
        shodan_loc_country_code_3 = shod.pop("loc_country_code_3")
        shodan_loc_country_code = shod.pop("loc_country_code")
        shodan_loc_country_name = shod.pop("loc_country_name")
        shodan_loc_postal_code = shod.pop("loc_postal_code")
        shodan_loc_dma_code = shod.pop("loc_dma_code")
        shod.clear() 

        #Get ThreatCrowd Data
        tc_data = get_threatcrowd(addr)#returns a dictionary
       
        hashes = tc_data.pop("hashes")#this key returns a list
        hashstring = ""
        if len(hashes) == 0:
            hashstring = "None found"
        for x in range(len(hashes)):
            entry = hashes[x]
            hashstring = hashstring + entry
        tc_hashes = hashstring
        
        tc_permalink = tc_data.pop("permalink")

        ref = tc_data.pop("references")#this key returns a list
        refstring = ""
        if len(ref) == 0:
            refstring = "None found"
        for x in range(len(ref)):
            entry = ref[x]
            refstring = refstring + entry
        tc_references = refstring

        dom = tc_data.pop("domain_resolutions")#this key returns a list
        domstring = ""
        if len(dom) == 0:
            domstring = "None found"
        for x in range(len(dom)):
            entry = dom[x]
            domstring = domstring + entry
        tc_domain_resolutions = domstring
        
        tc_verdict = tc_data.pop("verdict_response_code")
        tc_data.clear()


        #Get WhoIs Data
        try:
           
            obj = IPWhois(addr, timeout=20)
            results = obj.lookup_rdap()#default depth is 0, we only need top level values for the file

            whois_asn = (newline_clean(results['asn']))
            whois_asn_country_code = (newline_clean(results['asn_country_code']))
            whois_network_cidr = (newline_clean(results['network']['cidr']))
            tmp_links = (newline_clean(results['network']['links']))
            for i in range(len(tmp_links)):
                if i == 0:
                    contact_info_link1 = tmp_links[0]
                elif i == 1:
                    contact_info_link2 = tmp_links[1]
                elif i == 2:
                    contact_info_link3 = tmp_links[2]  

            #Entry identifier - this is the Internet Registry Number, known as the handle Ex:ZG39-ARIN for Google
            for object_key, object_dict in results['objects'].items():
                whois_handle = str(object_key)
                if results['objects'] is not None:
                    for k in results['objects']:
                        #Address - first result only
                        tmp_add = results['objects'][k]['contact']['address']
                        if tmp_add is not None:
                            whois_contact_address = str(newline_clean(tmp_add[0]['value']))

                        #Phone - first result only
                        tmp_ph = results['objects'][k]['contact']['phone']
                        if tmp_ph is not None:
                            whois_contact_phone = str(phone_clean(tmp_ph[0]['value']))

                        #Name - string result
                        tmp_nm = results['objects'][k]['contact']['name']
                        if tmp_nm is not None:
                            whois_contact_name = str(newline_clean(tmp_nm))

                        #Title - string result
                        tmp_ti = results['objects'][k]['contact']['title']
                        if tmp_ti is not None:
                            whois_contact_title = str(newline_clean(tmp_ti))

                        #Role - string result
                        tmp_ro = results['objects'][k]['contact']['role']
                        if tmp_ro is not None:
                            whois_contact_role = str(newline_clean(tmp_ro))

            #Create Entry
            writer.writerow({"ip_addr" : addr,
                             "whois_abuse_email" :  whois_abuse_email,
                             "whois_handle" : whois_handle,
                             "whois_asn" : whois_asn,
                             "whois_asn_country_code" : whois_asn_country_code,
                             "whois_network_cidr" : whois_network_cidr,
                             "whois_contact_address" : whois_contact_address,
                             "whois_contact_emails" : whois_send_to,
                             "whois_contact_phone" : whois_contact_phone,
                             "whois_contact_name" : whois_contact_name,
                             "whois_contact_title" : whois_contact_title,
                             "whois_contact_role" : whois_contact_role,
                             "whois_contact_info_link1" : whois_contact_info_link1,
                             "whois_contact_info_link2" : whois_contact_info_link2,
                             "whois_contact_info_link3" : whois_contact_info_link3,
                             "MaxMind_ip_iso_code" : MaxMind_ip_iso_code,
                             "MaxMind_ip_country" : MaxMind_ip_country,
                             "MaxMind_ip_state" : MaxMind_ip_state,
                             "MaxMind_ip_city" : MaxMind_ip_city,
                             "MaxMind_ip_zipcode": MaxMind_ip_zipcode,
                             "shodan_timestamp" : shodan_timestamp,
                             "shodan_os" : shodan_os,
                             "shodan_product" : shodan_product,
                             "shodan_isp" : shodan_isp,
                             "shodan_asn" : shodan_asn,
                             "shodan_org" : shodan_org,
                             "shodan_hostnames" : shodan_hostnames,
                             "shodan_domains" : shodan_domains,
                             "shodan_ports" : shodan_ports,
                             "shodan_loc_city" : shodan_loc_city,
                             "shodan_loc_region_code" : shodan_loc_region_code,
                             "shodan_loc_are_code" : shodan_loc_are_code,
                             "shodan_loc_longitude" : shodan_loc_longitude,
                             "shodan_loc_latitiude" : shodan_loc_latitiude,
                             "shodan_loc_country_code_3" : shodan_loc_country_code_3,
                             "shodan_loc_country_code" : shodan_loc_country_code,
                             "shodan_loc_country_name" : shodan_loc_country_name,
                             "shodan_loc_postal_code" : shodan_loc_postal_code,
                             "shodan_loc_dma_code" : shodan_loc_dma_code,
                             "threatcrowd_hashes" : tc_hashes,
                             "threatcrowd_permalink" : tc_permalink,
                             "threatcrowd_references" : tc_references,
                             "threatcrowd_domains_resolved_date" : tc_domain_resolutions,
                             "threatcrowd_verdict" : tc_verdict})

        except Exception as e:
            #FWIW, there's much better ways to log errors, but I don't need it for what I am doing
            writer.writerow({"ip_addr" : addr,
                             "whois_abuse_email" : "-",
                             "whois_handle" : "Error while pulling data",
                             "whois_asn" : "-",
                             "whois_asn_country_code" : "-",
                             "whois_network_cidr" : "-",
                             "whois_contact_address" : "-",
                             "whois_contact_emails" : "-",
                             "whois_contact_phone" : "-",
                             "whois_contact_name" : "-",
                             "whois_contact_title" : "-",
                             "whois_contact_role" : "-",
                             "whois_contact_info_link1" : "-",
                             "whois_contact_info_link2" : "-",
                             "whois_contact_info_link3" : "-",
                             "MaxMind_ip_iso_code" : "-",
                             "MaxMind_ip_country" : "-",
                             "MaxMind_ip_state" : "-",
                             "MaxMind_ip_city" : "-",
                             "MaxMind_ip_zipcode": "-",
                             "shodan_timestamp" : "-",
                             "shodan_os" : "-",
                             "shodan_product" : "-",
                             "shodan_isp" : "-",
                             "shodan_asn" : "-",
                             "shodan_org" : "-",
                             "shodan_hostnames" : "-",
                             "shodan_domains" : "-",
                             "shodan_ports" : "-",
                             "shodan_loc_city" : "-",
                             "shodan_loc_region_code" : "-",
                             "shodan_loc_are_code" : "-",
                             "shodan_loc_longitude" : "-",
                             "shodan_loc_latitiude" : "-",
                             "shodan_loc_country_code_3" : "-",
                             "shodan_loc_country_code" : "-",
                             "shodan_loc_country_name" : "-",
                             "shodan_loc_postal_code" : "-",
                             "shodan_loc_dma_code" : "-",
                             "threatcrowd_hashes" : "-",
                             "threatcrowd_permalink" : "-",
                             "threatcrowd_references" : "-",
                             "threatcrowd_domains_resolved_date" : "-",
                             "threatcrowd_verdict" : "-"})
                             
            with open(errors_file,"a") as ferr:
                ferr.write("Unexpected error getting WhoIs info for: "+addr)
                ferr.write("\n")

        work = work-1

sys.exit("ip_hunter script complete")
