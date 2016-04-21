#!/usr/bin/python
'''
Python 3.5 compatible
Creates a tab delimited output file - next version of this will create a CSV
Dependendcies
  * ipwhois version 13
  * pprintpp 2.3 (prety print plus plus)
It leverages the new RDAP structure and gathers 
    addr - ip addres from your input as 
    handle - unique identifier user by Internet Registration Centers
    asn - autonomous system number
    asn_country_code 
    network_cidr 
    contact_address 
    contact_email 
    contact_phone 
    contact_name 
    contact_title
    contact_role
You can modify this script with a few loops to get EVERYTHING out of RDAP if you wish. At the time of this writing I only needed to gather the first set of contact info for each onbject
You can also uncomment the pp(results) and get the output in a very, very nice format.
'''
import datetime
import os.path
import sys
from ipwhois import IPWhois
from pprintpp import pprint as pp

def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

def tab_add(entry):
    #print("adding tabs to "+entry)
    try:
        tabbed = (entry+"\t")
    except:
        tabbed = "UNK\t"
        #print("Error trying to add tab to: "+tabbed)
        with open(errors_file,"a") as ferr:
            ferr.write("Unexpected error adding tab to: "+entry)
            ferr.write("\n")
    return tabbed

def newline_clean(original):
  cleaned = original
    try:
        cleaned = original.replace("\n","|").replace("\r","|")
    except: continue #shame on me for this
    return cleaned


dt = datetime.date.today()
input_path = "/path/to/myinput/"
input_name = "filename.txt"
input_file_name = os.path.join(input_path, input_name)
output_path = "/path/to/myoutput/"
output_name = ("IP_details_"+str(dt)+".txt")
output_file_name = os.path.join(output_path, output_name)
process_file_name = os.path.join(input_path,"cleaned_input.txt")
errors_file = os.path.join(output_path,"processing errors.txt")

#sort file and stripout blank lines
with open(input_file_name,'r') as f, open(process_file_name,"w")as f2:
    for line in sorted(f):
        if len(line) > = 7: #a proper ip address will be at least 1.1.1.1
            line.strip().replace(" ","")
            f2.write(line)

work = file_len(process_file_name)
print(str(work)+" ips to process\n")

with open(process_file_name,"r") as fin, open(output_file_name,"w",encoding="ascii", errors="ignore") as fout:
    addr = "UNK\t"
    handle = "UNK\t"
    asn = "UNK\t"
    asn_country_code = "UNK\t"
    network_cidr = "UNK\t"
    contact_address = "UNK\t"
    contact_email = "UNK\t"
    contact_phone = "UNK\t"
    contact_name = "UNK\t"
    contact_title = "UNK\t"
    contact_role = "UNK\t"
    
    #write file header
    fout.write("addr\thandle\tasn\tasn_country_code\tnetwork_cidr\tcontact_address\tcontact_email\tcontact_phone\tcontact_name\tcontact_title\tcontact_role\n")

    for line in fin:
        addr = line.rstrip().strip()
        print("Processing "+str(addr)+" "+str(work)+" more IP's to go")

        #Get WhoIs Data
        try:
            obj = IPWhois(addr, timeout=20)
            results = obj.lookup_rdap(depth=1)
            asn = tab_add(newline_clean(results['asn']))
            #print("ASN: "+asn)
            asn_country_code = tab_add(newline_clean(results['asn_country_code']))
            #print("ASN Country Code: "+asn_country_code)
            network_cidr = tab_add(newline_clean(results['network']['cidr']))
            #print("Network CIDR: "+network_cidr)
            #Entry identifier - this is the Internet Registry Number, known as the handle Ex:ZG39-ARIN for Google
            for object_key, object_dict in results['objects'].items():
                handle = str(object_key)
                handle = tab_add(handle)
                #print("Handle: "+handle)
                if results['objects'] is not None:
                    for k in results['objects']:
                        #Address - first result only
                        tmp_add = results['objects'][k]['contact']['address']
                        if tmp_add is not None:
                            contact_address = tab_add(newline_clean(tmp_add[0]['value']))
                            #print("Address: "+contact_address)

                        #Email - first result only
                        tmp_em = results['objects'][k]['contact']['email']
                        if tmp_em is not None:
                            contact_email = tab_add(newline_clean(tmp_em[0]['value']))
                            #print("Email: "+contact_email)

                        #Phone - first result only
                        tmp_ph = results['objects'][k]['contact']['phone']
                        if tmp_ph is not None:
                            contact_phone = tab_add(newline_clean(tmp_ph[0]['value']))
                            #print("Phone: "+contact_phone)

                        #Name - string result
                        tmp_nm = results['objects'][k]['contact']['name']
                        if tmp_nm is not None:
                            contact_name = tab_add(newline_clean(tmp_nm))
                            #print("Name: "+contact_name)

                        #Title - string result
                        tmp_ti = results['objects'][k]['contact']['title']
                        if tmp_ti is not None:
                            contact_title = tab_add(newline_clean(tmp_ti))
                            #print("Title: "+contact_title)

                        #Role - string result
                        tmp_ro = results['objects'][k]['contact']['role']
                        if tmp_ro is not None:
                            contact_role = tab_add(newline_clean(tmp_ro))
                            #print("Role: "+contact_role)

            #Create Output File
            addr = tab_add(addr)
            entry = str(addr + handle + asn + asn_country_code + network_cidr + contact_address + contact_email + contact_phone + contact_name + contact_title + contact_role)
            fout.write(entry)
            fout.write("\n")

        except Exception as e:
            with open(errors_file,"a") as ferr:
                ferr.write("Unexpected error getting WhoIs info for: "+addr)
                ferr.write("\n")

        work = work-1

print("done")
