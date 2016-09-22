#!/usr/bin/python
'''
For my Windows users!
Written using Python3
This script should do 3 or 4 things, depending on how you count:
1.  Take a single URL to a file as input
    pull it down
    submit it Threat Grid - return the URL for the sample run
2.  Read in a file of targets, parse each line,
    submit each one to Threat Grid

Contributors to this script include: tazz, pr00f
'''

import argparse
import datetime
import os
import pprint as pp
import requests
import sys
import validators

dt = datetime.date.today()

##################################################################
#                         GET API KEYS                           #
##################################################################

#There are much more secure ways to do this, update this later
tg_credfile = os.path.expanduser('~/api_creds/tgapi.txt')
with open(tg_credfile,'r') as tg_creds:
    tgkey = tg_creds.readline().strip()

vtkey = ""
vtuser = ""
vt_credfile = os.path.expanduser('~/api_creds/vtapi.txt')
with open(vt_credfile,'r') as vt_creds:
    vtuser = vt_creds.readline().strip()
    vtkey = vt_creds.readline().strip()

##################################################################
#                         FUNCTIONS                              #
##################################################################

def set_directory():
    here = os.getcwd()
    path = os.path.join(here,"Grab_n_Go_Results",str(dt))
    if os.path.isdir(path):
        return path
    else:
        try:
            os.makedirs(path)
        except FileExistsError as e:
            sys.exit("Error: Output path {0} exists already.  SYSTEM ERROR: {1}".format(path, e))
        except OSError as e:
            sys.exit("Error: Output path {0} exists already.  SYSTEM ERROR: {1}".format(path, e))
    return path


def setup_output(output_destination, output_file_name):
    #this function ensures that we don't overwrite files with the same name
    #if the file already exists, we will prepend the file name with a number and underscore
    #we want to preserve the extension as the sandboxes will need that
    count = 0
    outfile = os.path.join(output_destination, output_file_name)
    exists = os.path.isfile(outfile)
    while exists:
        new_name = "{0}_{1}".format(str(count),output_file_name)
        outfile = os.path.join(output_destination, new_name)
        count += 1
        exists = os.path.isfile(outfile)
    return outfile

def get_single_sample(url, output_destination=None, output_file_name=None, attempt_number=1):
    print("Trying to get the sample")
    if output_file_name is None:
         output_file_name = url.split('/')[-1]
    if output_destination is None:
        output_destination = set_directory()
    outfile = setup_output(output_destination, output_file_name)
    max_attempts = 3
    attempt = attempt_number
    try:
        r = requests.get(url, timeout=(3.5, 30), stream=True)  
        with open(outfile, 'wb') as fout:
            for chunk in r.iter_content(1024): 
                if chunk: # filter out keep-alive new chunks
                    fout.write(chunk)
        fout.close()
        pp.pprint(tgSubmitFile(outfile, options={'private':1}))

    except requests.exceptions.HTTPError as e:
        print("HTTPError Error for {0} \n{1}".format(target, e))
        return

    except requests.exceptions.ConnectionError as e:
        print("Connection Error for {0} \n{1}".format(target, e))
        return

    except requests.exceptions.Timeout:
        if attempt_number < max_attempts:
            attempt += 1
            return get_single_sample(url, attempt_number=attempt)
        else:
            print("Timeout Error. Attempted {0} times to get {1}".format(max_attempts, url))
            return

    except requests.exceptions.TooManyRedirects:
        print("Too many redirects when trying to get {0}".format(target))
        return

    except requests.exceptions.RequestException as e:
        print("RequestException Error for {0} \n{1}".format(target, e))
        return

    return

def get_multiple_samples(source_list):
    print("Processing input file to fetch samples")
    output_destination = set_directory()
    print(source_list)
    for x in range(len(source_list)):
        print(str(x))
        target = source_list[x]
        output_file_name = target.split('/')[-1]
        outfile = setup_output(output_destination, output_file_name)
        try:
            print("Trying to get {0}".format(target))
            r = requests.get(target, timeout=(3.5, 30), stream=True)  
            with open(outfile, 'wb') as fout:
                for chunk in r.iter_content(1024): 
                    if chunk: # filter out keep-alive new chunks
                        fout.write(chunk)
            fout.close()
            pp.pprint(tgSubmitFile(outfile, options={'private':1}))

        except requests.exceptions.HTTPError as e:
            print("HTTPError Error for {0} \n{1}".format(target, e))
            return

        except requests.exceptions.ConnectionError as e:
            print("Connection Error for {0} \n{1}".format(target, e))
            return

        except requests.exceptions.Timeout:
            print("Timeout Error for {0} \n{1}".format(target, e))
            return

        except requests.exceptions.TooManyRedirects:
            print("Too many redirects when trying to get {0}".format(target))
            return

        except requests.exceptions.RequestException as e:
            print("RequestException Error for {0} \n{1}".format(target, e))
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

##################################################################
#                         MAIN                                   #
##################################################################

parser = argparse.ArgumentParser()
#INPUT: single url
parser.add_argument("-url",
                    help='''The url you want to grab a file from ex:http://judo-club-solesmois-59.fr/bin/dll.exe.
You may use this with the --o parameter to sepcify a specific name four your output file''')

#OUTPUT: specify a destination path and file name, ONLY USED WITH -url
parser.add_argument("-o", "--ofile", "--outfile",
                    help='''Is used with the -url command the path and name of the output file you want to use.
If the file exists, it will be overwritten
You can only use this option if you are providing a url at the command line.''')

#INPUT: source file (with path)
parser.add_argument("-f", "--file",
                    help='''Is the input file name and path ex: ~/BadStuff/input/badthingslist.txt
Contenst should be in this format http://judo-club-solesmois-59.fr/bin/dll.exe, one per line.
You can use the --dir command to specify where your output should go.  File names will be the same as the source.''')

args = parser.parse_args()
outputfilename = None
outputdestination=None

#check to make sure that at least a URL or an input file was provided

if not args.url and not args.file:
    sys.exit("Error:  You must provide a URL or a File of URLs at a minimum.")

if args.url and args.file:
    sys.exit("Error:  Provide one or the other, but not both a URL and an input file.")


if args.url:
    if validators.url(args.url):
        if args.ofile:
            outputfilename = os.path.basename(args.ofile)
            print(outputfilename)
            outputdestination = os.path.dirname(args.ofile)
            print(outputdestination)
            if os.path.exists(outputdestination):
                outputfile = args.ofile
                try:
                    with open(outputfile,"wb") as fout:
                        fout.seek(0)
                except PermissionError as e:
                    sys.exit("Error:  You did not have permssion to write to" +
                            "this destination.  Ensure you provided a file name" +
                            "and have permssion to write to the directory.")
            else: sys.exit("Error:  You did not provide a valid path and filename")
        get_single_sample(args.url, output_destination=outputdestination, output_file_name=outputfilename)
    else:
        #try to help and see if they forgot the protocol at the beginning
        protocol = "http://"
        fixedurl = protocol + args.url
        print(fixedurl)
        if validators.url(fixedurl):
            get_single_sample(fixedurl, output_destination=outputdestination, output_file_name=outputfile)
        else:
            sys.exit("Error: not a valid URL format {0}. Probably missing the protocol http or https ://".format(args.url))

if args.file:
    if os.path.isfile(args.file):
        targets = list()
        with open(args.file, "r") as fin:
            for line in fin:
                target = line.strip()
                print("Reading in {0}".format(target))
                if validators.url(target):
                    targets.append(target)
                else:
                    #try to help and see if they forgot the protocol at the beginning
                    protocol = "http://"
                    fixedurl = protocol + target
                    if validators.url(fixedurl):
                        targets.append(target)
                    else:
                        print("Invalid URL format, {0} was not processed.".format(target))
        if targets:
            get_multiple_samples(targets)
        else:
            sys.exit("Error: Your sourcelist did not have any properly formatted URLs, nothing has been processed.")
