'''
Language & Version:  Python 3.4
This script looks in each line for the : character.  If it's there, the line is written to a new file.   
If it is not then it is discarded.  
'''

import csv
import datetime
import os
import os.path


input_path = str(input("Enter the *PATH ONLY* to the list of IPs is at that you want to look up: "))
input_name = str(input("Enter the name of the file containing the IPs (include the extension): "))
output_path = str(input("Enter the *PATH ONLY* to where you want to save your file: "))
output_name = str(input("What do you want to name YOUR file? (A date will be added automatically and it will get a .txt extension) "))
dt = datetime.date.today()
output_name = (output_name+"_"+str(dt)+".txt")

output_file_name = os.path.join(output_path, output_name)
input_file_name = os.path.join(input_path, input_name)


datafield = ":" #used to identify rows that have data we want to keep

#stripout blank lines from the source file
with open(input_file_name,'r') as f1, open(output_file_name,"w")as f2:
    for line in f1:
        line.strip()
        if datafield in line:
            f2.write(line)
