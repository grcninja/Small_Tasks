'''
Python 3.5.1

SUMMARY:  Pulls data from Virus Total and Domain Tools based on IPV4 address

Please note the current user needs an "api_creds" directory in their home folder or C:/Users/JonDoe/ on a Windows box.
In there you should have two different .txt files, one called dtapi.txt and one vtapi.txt with a user name on the first line
and your api key on the second line

This is not the most secure way to handle credentials so I recommend implementing alternate methods if you have a security
requirements.

This script also leverages the powerful Requests module instead of usrlib stuff so the code below won't match exactly
to the examples you see on Virus Total's API documentation, but it achieves the same result with fewer lines

'''

import csv
import datetime
import dtapi.dtapi
import os
import pprint as pp
import requests
import sys

def get_dt_domains(ip):
    d = ""
    try:
        dt_response = dtapi.dtapi.reverse_ip(ip)
        for domain in dtapi.dtapi.domainlist_reverseip(dt_response):
            d = d + domain + ";"
    except: d = "N/A"
    return d

dt_credfile = os.path.expanduser('~/api_creds/dtapi.txt')
with open(dt_credfile,'r') as dt_creds:
    dtuser = dt_creds.readline().strip()
    dtkey = dt_creds.readline().strip()
dtapi.dtapi.configure(dtuser, dtkey, usessl=True)

vtkey = ""
vtuser = ""
vt_credfile = os.path.expanduser('~/api_creds/vtapi.txt')
with open(vt_credfile,'r') as vt_creds:
    vtuser = vt_creds.readline().strip()
    vtkey = vt_creds.readline().strip()

dt = datetime.date.today()
input_file_name = os.path.normcase(str(input('Enter the full path to your file, include the file name and extension: ')))
output_path = os.getcwd()
output_name = ("webshell_IP_reverse_search_"+str(dt)+".csv")
output_file_name = os.path.join(output_path, output_name)

with open(input_file_name, "r") as fin, open(output_file_name,"w",newline='',encoding="ascii", errors="ignore") as csvfile:
    domains = ""
    hashes_undetected = ""
    hashes_detected = ""
    URLs = ""
    hostnames = ""
    vt_as_owner = ""
    vt_asn = ""
    vt_country = ""
    fieldnames = ["ip",
                  "dt_domains",
                  "vt_asn",
                  "vt_as_owner",
                  "vt_country",
                  "vt_ip_to_sha256_undetected",
                  "vt_ip_to_sha256_detected",
                  "vt_ip_to_detected_urls",
                  "vt_ip_to_hostnames"]

    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for line in fin:
        target = line.strip()
        domains = get_dt_domains(target)
        print("Processing {}".format(target))
        try:
            parameters = {'ip': target, 'apikey': vtkey}
            r = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', params=parameters)
            vt_response_dict = r.json()
            if str(vt_response_dict['response_code']) == '1':
                vt_as_owner = vt_response_dict['as_owner']
                vt_asn = vt_response_dict['asn']
                vt_country = vt_response_dict['country']
                if 'detected_communicating_samples' in vt_response_dict and len(vt_response_dict['detected_communicating_samples']) > 0:
                    for x in range(len(vt_response_dict['detected_communicating_samples'])):
                        sha256 = vt_response_dict['detected_communicating_samples'][x]['sha256']
                        dcs_date = vt_response_dict['detected_communicating_samples'][x]['date']
                        entry = sha256 + "/" + dcs_date
                        hashes_detected = hashes_detected + entry + ";"
                else: hashes_detected = "None found"
                if 'undetected_communicating_samples' in vt_response_dict and len(vt_response_dict['undetected_communicating_samples']) > 0:
                    for x in range(len(vt_response_dict['undetected_communicating_samples'])):
                        sha256 = vt_response_dict['undetected_communicating_samples'][x]['sha256']
                        udcs_date = vt_response_dict['undetected_communicating_samples'][x]['date']
                        entry = sha256 + "/" + dcs_date
                        hashes_undetected = hashes_undetected + entry + ";"
                else: hashes_undetected = "None found"
                if 'detected_urls' in vt_response_dict and len(vt_response_dict['detected_urls']) > 0:
                    for x in range(len(vt_response_dict['detected_urls'])):
                        url = vt_response_dict['detected_urls'][x]['url']
                        URLs = URLs + url + ";"
                else: URLs = "None found"
                if 'resolutions' in vt_response_dict and len(vt_response_dict['resolutions']) > 0:
                    for x in range(len(vt_response_dict['resolutions'])):
                        hostname = vt_response_dict['resolutions'][x]['url']
                        hostnames = hostnames + hostname + ";"
                else: hostnames = "None found"
            if str(vt_response_dict['response_code']) == '0':
                hashes_undetected = "None found"
                hashes_detected = "None found"
                URLs = "None found"
                hostnames = "None found"
            if str(vt_response_dict['response_code']) == '-1':
                hashes_undetected = "invalid IP format"
                hashes_detected = "invalid IP format"
                URLs = "invalid IP format"
                hostnames = "invalid IP format"
        except:
            hashes_undetected = "error in VT"
            hashes_detected = "error in VT"
            URLs = "error in VT"
            hostnames = "error in VT"
        writer.writerow({"ip": target,
                         "dt_domains" : domains,
                         "vt_asn" : vt_asn,
                         "vt_as_owner" : vt_as_owner,
                         "vt_country" : vt_country,
                         "vt_ip_to_sha256_undetected" : hashes_undetected,
                         "vt_ip_to_sha256_detected" : hashes_detected,
                         "vt_ip_to_detected_urls" : URLs,
                         "vt_ip_to_hostnames" : hostnames})

print("complete")
