#!env python
#credit to c0mmiebstrd for his significant help optimizing this 
'''
v2.4 changes:
*  fixed logic error for determining if the CVE is not in the source
*  updated the _cve_details_summary report to reflect if CVE known
'''
import json
import requests
import sys
from datetime import datetime
from bs4 import BeautifulSoup
import os
import re
import argparse

dt = datetime.now().strftime("%Y%m%d_%H%m%S")
valid_cve = re.compile("CVE-\d{4}-\d{4,9}?",flags=re.IGNORECASE)

class CVE():
    def __init__(self,
                 cve,
                 out_dir,
                 url="http://www.cvedetails.com/cve-details.php"):
        self.cve = cve        # CVE-2017-0001
        self.url = url        # cvedetails.com/
        self.out = out_dir    # ./{data,results}
        self.soup = None      # bs4
        self.isunknown = False
        self.exploits = {
            "metasploit": None,
            "exploitdb": None
        }

    def write_html(self, html):
        path = self.out["data"]+self.cve.replace("-", "_")+".html"
        with open(path, "wb") as f:
            f.write(html)

    def get(self):
        req = None
        try:
            req = requests.get(url=self.url,
                               params={"cve_id":self.cve},
                                #stream=True,
                                timeout=30
            )
        except:
            print("Request failed: %s" % self.url)
            return
        # process output based on response code
        if req.status_code != 200: # error
            print("%s returned a %d status code when trying   \
                  to find results".format(self.cve,req.status_code))
            self.write_html("{} is status code: {}".format(self.url,
                                                    req.status_code))
            # invalidate this cve
            self.cve = None
            self.out = None
        else: # good!!
            #content_enconding = req.content
            self.write_html(req.text.encode('utf8'))
            #self.soup = BeautifulSoup(req.text, "html.parser")
            self.soup = BeautifulSoup(req.text.encode('utf8'), "lxml")

    def find_links(self, linktext, tag="a", tag_is_id=False):
        # tag - html tag to search for
        # linktext - regex or string to search found tags for
        if not self.soup:
            return list()
        links = None
        if tag_is_id:
            links = self.soup.find(id=tag)
        else:
            links = self.soup.find(tag)
        results = list()
        #if the tag does not exist in the soup, links is not update
        if links is None:
            return results
        try:
            for link in links.find_all("a"):
                # transform found links into appropriate strings
                link = str(link.get("href"))
                # determine linktext type and validate str(link) against.
                if (isinstance(linktext, str) and linktext in link) \
                        or (isinstance(linktext, re._pattern_type)
                            and linktext.search(link)):
                    results.append(link)
            return results
        except:
            print ("{} created an error.\nThe soup is:\n {}".format(self.cve, self.soup.prettify()))
            return results#


    def find_msf(self):
        msf_exists = "https://www.rapid7.com/db/modules/exploit"
        links = self.find_links(linktext=msf_exists,
                                tag="metasploitmodstable",
                                tag_is_id=True)
        if len(links) != 0:
            self.exploits["metasploit"] = links

    def find_edb(self):
        edb_exists = "http://www.exploit-db.com/exploits"
        links = self.find_links(linktext=edb_exists,
                                tag="vulnrefstable",
                                tag_is_id=True)
        if len(links) != 0:
            self.exploits["exploitdb"] = links


    def find_unknown(self):
        unk_exists = "Unknown CVE ID"
        unk = self.soup.find_all(string="Unknown CVE ID")
        for item in unk:
            if unk_exists in item:
                self.isunknown = True

    def write_summary(self, report_file):
        entry = {
            "CVE": self.cve,
            "Not in Source:":self.isunknown,
            "Metasploit": self.exploits["metasploit"],
            "ExploitDB": self.exploits["exploitdb"]
        }
        report_file.write(json.dumps(entry,
                                     indent = 2,
                                     sort_keys = True))

    def write_exploits(self, out_file):
        exploits = {"metasploit":"",
                    "exploitdb":""}  # key is same in self and dict
        for key in exploits.keys():
            if self.exploits[key]: # key is not None
                # assign self values to dict with "exp,exp,exp"
                exploits[key] = ",".join(self.exploits[key])
        entry = "{},{},{}\n".format(self.cve,
                                    exploits["metasploit"],
                                    exploits["exploitdb"])
        out_file.write(entry)


def parse_args():
    result = {
        "cves": None,   # [cve, cve, cve]
        "output": None, # {data:path, reports:path}
    }
    # build and gather arguments
    args = argparse.ArgumentParser(
        description="Generates reports for publicly available "
                    "exploits from csv lists of CVEs"
    )
    args.add_argument("-c",
                      "--cve",
                      metavar="CVE-2017-0001",
                      type=str,
                      help="Single CVE or quoted list with commas")
    args.add_argument("-f",
                      "--file",
                      metavar="./cves.csv",
                      type=str,
                      help="File of CVEs in csv or newline separated "
                           "list")
    args.add_argument("-o",
                      '--output',
                      metavar="./reports",
                      type=str,
                      help="Path to output folder")
    args = args.parse_args()
    # validation, allow only -c or -f
    if args.cve and args.file:
        print("Provide only '-c' or '-f' not both, exiting.")
        sys.exit(1)
    # input args
    if args.cve:
        # grab all cves from cli, only adding if valid
        result["cves"] = [cve for cve in args.cve.split(",")
                          if valid_cve.match(cve)]
    elif args.file:
        # open and read file by line, appending valid cves
        cves = list()
        with open(args.file) as f:
            for line in f.readlines():
                line = line.strip()
                if valid_cve.match(line):
                    cves.append(line)
        result["cves"] = cves
    # output arg, defaults to "./ResultsCVEdetails"
    path = args.output if args.output else "./ResultsCVEdetails"
    result["output"] = {"data":path+"/data/",
                        "reports":path+"/reports/"}
    # check for and generate output folders
    for key in result["output"].keys():
        folder = result["output"].get(key)
        if not os.path.exists(folder):
            os.makedirs(folder)
    return result

if __name__ == "__main__":
    # # dict( cves=list(cve as str), output=dict(data, reports))
    args = parse_args()
    # build list of CVE objects from args list of cves
    cves = [CVE(cve, args["output"]) for cve in args["cves"]]
    for cve in cves:
        cve.get()          # pull and store html content
        cve.find_unknown() # parse for evidence CVE not in their db
        cve.find_msf()     # parse for msf modules
        cve.find_edb()     # parse for exploitdb
    # write reports for all cves
    summary = os.path.join(args["output"]["reports"],
                           "_cve_details_summary_{}".format(dt))
    with open(summary, "w") as sum_report:
        #[cve.write_summary(report) for cve in cves]
        for cve in cves:
            cve.soup = None
            cve.write_summary(sum_report)
    #write a report with only cves that have exploits
    exploit_report = os.path.join(args["output"]["reports"],
                                  "_cve_exploits_{}".format(dt))
    #[cve.write_summary(report) for cve in cves]
    for cve in cves:
        if cve.exploits.get("metasploit") \
                or cve.exploits.get("exploitdb"):
            with open(exploit_report, "a") as exp_report:
                    cve.write_exploits(exp_report)
