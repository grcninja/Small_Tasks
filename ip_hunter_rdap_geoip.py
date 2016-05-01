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


Dependencies on:
* geoip2 2.3.0
* ipwhois3 0.13
* shodan 1.5.3
'''
import csv
import datetime
import geoip2.database
import os.path
import pprintpp as pp #used for troubleshooting type pp.pprint(stuff)
import shodan
import sys
from ipwhois import IPWhois


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
        self.api = shodan.Shodan("YOUR API KEY HERE")
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


dt = datetime.date.today()
input_path = str(input("Enter the path to the ip list? "))
input_name = str(input("Enter the name of the ip list (include the extension)? "))
input_file_name = os.path.join(input_path, input_name)
output_path = str(input("Enter the path you want your output written to.\n Note your output file will be called IP_details_$date_.csv: "))
output_name = ("IP_details_"+str(dt)+".csv")
output_file_name = os.path.join(output_path, output_name)
process_file_name = os.path.join(input_path,"cleaned_input.txt")
errors_file = os.path.join(output_path,"processing errors.txt")

#sort file and stripout blank lines
with open(input_file_name,"r") as f, open(process_file_name,"w")as f2:
    seen = set()
    for line in f:
        line.strip(" \n\t\r abcdefghijklmnopqrstuvwxyz")
        if line in seen: continue
        f2.write(line)
        seen.add(line)

maxmind_db_file_path = str(input("Where is the Maxmind GeoIP2-City.mmdb file? "))
maxmind_db_name = str(input("What did you name the mmdb file (inlude .mmdb in your reply)? "))
maxmind_db_path = os.path.join(maxmind_db_file_path, maxmind_db_name)

geoip = GeoDB(maxmind_db_path)
showme = ShodanNode()

work = file_len(process_file_name)
print(str(work)+" ips to process\n")

with open(process_file_name,"r") as fin, open(output_file_name,"w",newline='',encoding="ascii", errors="ignore") as csvfile:

    #set up CSV file
    fieldnames = ["ip_addr" ,
                  "handle" ,
                  "asn" ,
                  "asn_country_code" ,
                  "network_cidr" ,
                  "contact_address" ,
                  "contact_emails" ,
                  "contact_phone" ,
                  "contact_name" ,
                  "contact_title" ,
                  "contact_role" ,
                  "contact_info_link1" ,
                  "contact_info_link2" ,
                  "contact_info_link3" ,
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
                  "shodan_loc_dma_code",]
    
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()


    
    for line in fin:
        addr = line.rstrip().strip()
        print("Processing {0}, {1} IPs remaining".format(addr,work-1))

        #set up Who is data variables
        handle = "None"
        asn = "None"
        asn_country_code = "None"
        network_cidr = "None"
        contact_address = "None"
        contact_emails = list()
        contact_phone = "None"
        contact_name = "None"
        contact_title = "None"
        contact_role = "None"
        contact_info_link1 = "None"
        contact_info_link2 = "None"
        contact_info_link3 = "None"       

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

        try:
            max_depth = 5
            email_entries = Emails(addr)
            contact_emails = email_entries.get_emails(max_depth)
            send_to = "none"
            if contact_emails is not None:
                send_to = ""
                for a in range(len(contact_emails)):
                    entry = contact_emails[a]
                    entry = entry + ";"
                    send_to = send_to + entry
        except:
            print("Well this isn't working")

        #Get WhoIs Data
        try:
           
            obj = IPWhois(addr, timeout=20)
            results = obj.lookup_rdap()#default depth is 0, we only need top level values for the file

            asn = (newline_clean(results['asn']))
            asn_country_code = (newline_clean(results['asn_country_code']))
            network_cidr = (newline_clean(results['network']['cidr']))
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
                handle = str(object_key)
                handle = (handle)
                if results['objects'] is not None:
                    for k in results['objects']:
                        #Address - first result only
                        tmp_add = results['objects'][k]['contact']['address']
                        if tmp_add is not None:
                            contact_address = str(newline_clean(tmp_add[0]['value']))

                        #Phone - first result only
                        tmp_ph = results['objects'][k]['contact']['phone']
                        if tmp_ph is not None:
                            contact_phone = str(phone_clean(tmp_ph[0]['value']))

                        #Name - string result
                        tmp_nm = results['objects'][k]['contact']['name']
                        if tmp_nm is not None:
                            contact_name = str(newline_clean(tmp_nm))

                        #Title - string result
                        tmp_ti = results['objects'][k]['contact']['title']
                        if tmp_ti is not None:
                            contact_title = str(newline_clean(tmp_ti))

                        #Role - string result
                        tmp_ro = results['objects'][k]['contact']['role']
                        if tmp_ro is not None:
                            contact_role = str(newline_clean(tmp_ro))

            #Create Entry
            writer.writerow({"ip_addr" : addr,
                             "handle" : handle,
                             "asn" : asn,
                             "asn_country_code" : asn_country_code,
                             "network_cidr" : network_cidr,
                             "contact_address" : contact_address,
                             "contact_emails" : send_to,
                             "contact_phone" : contact_phone,
                             "contact_name" : contact_name,
                             "contact_title" : contact_title,
                             "contact_role" : contact_role,
                             "contact_info_link1" : contact_info_link1,
                             "contact_info_link2" : contact_info_link2,
                             "contact_info_link3" : contact_info_link3,
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
                             "shodan_loc_dma_code" : shodan_loc_dma_code})

        except Exception as e:
            #FWIW, there's much better ways to log errors, but I don't need it for what I am doing
            writer.writerow({"ip_addr" : addr,
                             "handle" : "Error while pulling data",
                             "asn" : "-",
                             "asn_country_code" : "-",
                             "network_cidr" : "-",
                             "contact_address" : "-",
                             "contact_emails" : "-",
                             "contact_phone" : "-",
                             "contact_name" : "-",
                             "contact_title" : "-",
                             "contact_role" : "-",
                             "contact_info_link1" : "-",
                             "contact_info_link2" : "-",
                             "contact_info_link3" : "-",
                             "MaxMind_ip_iso_code" : "-",
                             "MaxMind_ip_country" : "-",
                             "MaxMind_ip_state" : "-",
                             "MaxMind_ip_city" : "-",
                             "MaxMind_ip_zipcode": "-",
                             "shodan_timestamp" : "-",
                             "shodan_os" : "-",
                             "shodan_product" :"-",
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
                             "shodan_loc_dma_code" : "-"})
                             
            with open(errors_file,"a") as ferr:
                ferr.write("Unexpected error getting WhoIs info for: "+addr)
                ferr.write("\n")

        work = work-1

print("done")
