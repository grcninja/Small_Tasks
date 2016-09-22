#!/usr/bin/python
'''
For Windows users who don't want to install wget or some other utility

This script should do 3 or 4 things, depending on how you count:
1.  Take a single URL to a file as input and pull it down.
NEXT: set up a parameter to read in a file of URLs
Contributors to this script include: tazz
'''

import argparse
import os
import requests
import sys
import validators


def setup_output(output_destination, output_file_name):
    #this function ensures that we don't overwrite files with the same name
    #if the file already exists, we will prepend the file name with a number and underscore
    #we want to preserve the extension as the sandboxes will need that
    count = 0
    if output_destination is None:
        here = os.getcwd()
        try:
            output_destination = os.mkdir(os.path.join(here,"Grab_n_Go_Results", url.split('/')[-1]))
        except FileExistsError as e:
            output_destination = os.path.join(here,"Grab_n_Go_Results")
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
        print("The file was saved to: {0}".format(outfile))

        #submit_toTG(fout)
        #submit_toTalosSandbox(fout)

    except requests.exceptions.HTTPError as e:
        print("{0}".format(e))

    except requests.exceptions.ConnectionError as e: 
        #put this here for logging to be done later
        print("{0}".format(e))

    except requests.exceptions.Timeout:
        if attempt_number < max_attempts:
            attempt = attempt_number + 1
            return get_sample(url, attempt_number=attempt)
        else:
            print("Timeout Error. Attempted {0} times to get {0}".format(max_attempts, url))

    except requests.exceptions.TooManyRedirects:
        print("Too many redirects when trying to get {0}".format(url))

    except requests.exceptions.RequestException as e:
        print("{0}".format(e))

    return r

def submitTG(sample):
    #submit sample to ThreatGrid
    #return the url or identifying value for the sample
    return None

def submitSandbox(sample):
    #submit sample to internal SandBox
    #return runID or identifying value for the sample
    return None


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
