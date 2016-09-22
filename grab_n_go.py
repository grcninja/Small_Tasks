#!/usr/bin/python
'''
This script should do 3 or 4 things, depending on how you count:
1.  Take a single URL to a file as input
    pull it down
    submit it Threat Grid - return the URL for the sample run

Contributors to this script include: tazz, pr00f
'''

import argparse
import datetime
import os
import requests
import sys
import validators

dt = datetime.date.today()
#There are much more secure ways to do this, update this later
tg_credfile = os.path.expanduser('~/api_creds/tgapi.txt')
with open(tg_credfile,'r') as tg_creds:
    tgkey = tg_creds.readline().strip()


def setup_output(output_destination, output_file_name):
    #this function ensures that we don't overwrite files with the same name
    #if the file already exists, we will prepend the file name with a number and underscore
    #we want to preserve the extension as the sandboxes will need that
    
    count = 0
    if output_destination is None:
        here = os.getcwd()
        try:
            output_destination = os.mkdir(os.path.join(here,"Grab_n_Go_Results",str(dt)))
        except FileExistsError as e:
            output_destination = os.path.join(here,"Grab_n_Go_Results",str(dt))
    outfile = os.path.join(output_destination, output_file_name)
    exists = os.path.isfile(outfile)
    while exists:
        new_name = "{0}_{1}".format(str(count),output_file_name)
        outfile = os.path.join(output_destination, new_name)
        count += 1
        exists = os.path.isfile(outfile)
    return outfile

def get_sample(url, output_destination=None, output_file_name=None, attempt_number=1):
    print("Trying to get the sample")
    if output_file_name is None:
         output_file_name = url.split('/')[-1]
    outfile = setup_output(output_destination, output_file_name)
    max_attempts = 3
    try:
        r = requests.get(url, timeout=(3.5, 30), stream=True)  
        with open(outfile, 'wb') as fout:
            for chunk in r.iter_content(1024): 
                if chunk: # filter out keep-alive new chunks
                    fout.write(chunk)
        fout.close()
        print(tgSubmitFile(outfile, options={'private':1}))

    except requests.exceptions.HTTPError as e:
        print("{0}".format(e))
        return

    except requests.exceptions.ConnectionError as e:
        print("{0}".format(e))
        return

    except requests.exceptions.Timeout:
        if attempt_number < max_attempts:
            attempt = attempt_number + 1
            return get_sample(url, attempt_number=attempt)
        else:
            print("Timeout Error. Attempted {0} times to get {0}".format(max_attempts, url))
            return

    except requests.exceptions.TooManyRedirects:
        print("Too many redirects when trying to get {0}".format(url))
        return

    except requests.exceptions.RequestException as e:
        print("{0}".format(e))
        return

    return


def tgSubmitFile(suspicious_sample,options={}):
    #credit for the bulk of this function goes to Colin Grady
    valid_options = [ 'os', 'osver', 'vm', 'private', 'source', 'tags' ]
    filename = os.path.basename(suspicious_sample)
    
    with open(suspicious_sample, "rb") as fd:
        file_data = fd.read()
    
    params = { 'api_key': tgkey, 'filename': filename}
    file = { 'sample': (filename, file_data) }

    for option in valid_options:
        if option in options:
            params[option] = options[option]

    # TODO: Submission response handling needs to be more robust

    try:
        resp = requests.post('https://panacea.threatgrid.com/api/v2/samples', params=params, files=file, verify=False)
    except:
        return False

    return resp.json()


parser = argparse.ArgumentParser()
parser.add_argument("-url", help="the url you want to grab a file from ex:http://judo-club-solesmois-59.fr/bin/dll.exe.  You may use this with the --o parameter to sepcify a specific name four your output file")
args = parser.parse_args()

#check to make sure that at least a URL or an input file was provided,
if not args.url:
    sys.exit("Error: You must provide a URL")

if args.url:
    if validators.url(args.url):
        get_sample(args.url, output_file_name=None)
    else:
        #try to help and see if they forgot the protocol at the beginning
        protocol = "http://"
        fixedurl = protocol + args.url
        print(fixedurl)
        if validators.url(fixedurl):
            get_sample(fixedurl, output_file_name=None)
        else:
            sys.exit("Error: not a valid URL format {0}. Probably missing the protocol http or https ://".format(args.url))

