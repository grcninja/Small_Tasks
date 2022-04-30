'''
This script pulls the raw csv files from https://github.com/simonhuwiler/uawardata
Prepends a date to the csv then
Adds a column for coords, which combines the lat & lng columns with a comma into one field
If you wish to use this with another csv on the web, note this code does not
account for the variety of ways someone names lattitude and longitude columns
it doesn't account for uppercase, abbreviations, misspellings etc.
If you with to use the regex compiled matches in lines 27 & 28 you are welcome
'''



import argparse
import datetime
import os
import pandas
import pandas as pd
from urllib.parse import urlparse
import re


dt = datetime.date.today()
dstr = dt.strftime("%Y%m%d")
dtm = datetime.datetime.now()
dtmstr = dstr+"_"+dtm.strftime("%H%M")
tm_HHmm = dtm.strftime("%H%M")
re_lat = re.compile('\blat*', re.IGNORECASE)  #regular expression to find lattitude, lat, LAT, LATTITUDE
re_lon = re.compile('/\bl[on][ng]/gm', re.IGNORECASE)  #same - but for longitutde


def add_location_col(url):
    df = pandas.DataFrame
    fp = urlparse(url).path
    fn = dtmstr + "_" + (os.path.basename(fp))
    dest = os.path.join(os.getcwd(),fn) #create a full path to the output file
    if not os.path.exists(dest):
        df = pd.read_csv(url, index_col=0, dtype=str, on_bad_lines='skip', delimiter=",")
        df["coord"] = df["lat"].astype(str)+","+df["lng"].astype(str)
        with open(dest, "w") as fout:
            df.to_csv(fout)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Script to pull from a web-based URL for a raw csv file format that "
                                                 "does not require authentication. It looks for a column named lat"
                                                 "and a column named lon",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-u", "--url",
                        action="store_true",
                        help="<Required> http://some/path/to/a.csv")
    print(parser.parse_args())
    results = parser.parse_args()  # collect cmd line args
    if not results.url:
        add_location_col("https://raw.githubusercontent.com/simonhuwiler/uawardata/master/data/csv/btgs_current.csv")
        add_location_col("https://raw.githubusercontent.com/simonhuwiler/uawardata/master/data/csv/units_current.csv")
        add_location_col("https://raw.githubusercontent.com/simonhuwiler/uawardata/master/data/csv/btgs_all.csv")
        add_location_col("https://raw.githubusercontent.com/simonhuwiler/uawardata/master/data/csv/units_all.csv")
    else:
        url = results.url
        update_data = add_location_col(url)
