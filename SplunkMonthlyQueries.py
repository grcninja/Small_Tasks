'''
Collection parameters
count = A number that indicates the maximum number of entities to
return. A value of "0" indicates no maximum.

offset = A number that
specifies the index of the first entity to return.

search = A string
that specifies a search expression to filter the response with, matching
field values against the search expression. For example, "search=foo"
matches any object that has "foo" as a substring in a field, and
"search=field_name%3Dfield_value" restricts the match to a single field.

sort_dir = An enum value that specifies how to sort entities. Valid
values are "asc" (ascending order) and "desc" (descending order).

sort_key = A string that specifies the field to sort by.

sort_mode = An enum value that specifies how to sort entities. Valid values are "auto",
"alpha" (alphabetically), "alpha_case" (alphabetically, case sensitive),
or "num" (numerically).

See the included text file Instructions_for_Queries for a description of
all the fields or go to http://dev.splunk.com/view/python-sdk/SP-CAAAEE5
for an explanation of the query properties

'''
import csv
import sys
import os

#GET THE LIBRARY BELOW FROM https://pypi.python.org/pypi/splunk-sdk/1.3.1 AS A .TAR.GZ FILE
#OR AS A ZIP FROM http://dev.splunk.com/view/SP-CAAADRV) then install the SDK
import splunklib.results as results

'''
The files listed in the Queries folder should be text files that have the parameters for the query identfied following a comma (,) character.
However, sometimes users do not follow the template correctly and we have to set values for them anyway.
Below are the default values that will be assigned if there is no parameter in the query file.
'''
search = ""
auto_cancel = 300
auto_finalize_ec = 0 #The number of events to process after which to auto-finalize the search. 0 means no limit.
auto_pause = 300 #The number of seconds of inactivity after which to automatically pause a job. 0 means never auto-pause.
earliest_time = "-30d" #EX: "2014-06-19T12:00:00.000-07:00" A time string that specifies the earliest time in the time range to search. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string. For a real-time search, specify "rt".
enable_lookups = False #A Boolean that indicates whether to apply lookups to events.
exec_mode = "normal" #An enum value that indicates the search mode ("blocking", "oneshot", or "normal").
force_bundle_replication = False #A Boolean that indicates whether this search should cause (and wait depending on the value of "sync_bundle_replication") bundle synchronization with all search peers.
_id = "" #A string that contains a search ID. If unspecified, a random ID is generated.
index_earliest = "" #A string that specifies the time for the earliest (inclusive) time bounds for the search, based on the index time bounds. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string.
index_latest = "" #A string that specifies the time for the latest (inclusive) time bounds for the search, based on the index time bounds. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string.
latest_time = "now" #EX: "2014-06-20T12:00:00.000-07:00" A time string that specifies the latest time in the time range to search. The time string can be a UTC time (with fractional seconds), a relative time specifier (to now), or a formatted time string. For a real-time search, specify "rt".
max_count = 1000 #The number of events that can be accessible in any given status bucket.
max_time = 7200
namespace = "" #A string that contains the application namespace in which to restrict searches.
now = time.gmtime()
reduce_freq = 0 #The number of seconds (frequency) to run the MapReduce reduce phase on accumulated map values.
reload_macros = True #A Boolean that indicates whether to reload macro definitions from the macros.conf configuration file.
remote_server_list = "" #A string that contains a comma-separated list of (possibly wildcarded) servers from which to pull raw events. This same server list is used in subsearches.
rf = "clientip host req_time method referer uri_path user useragent _raw" #A string that adds one or more required fields to the search.
rt_blocking = False #A Boolean that indicates whether the indexer blocks if the queue for this search is full. For real-time searches.
rt_indexfilter = False #A Boolean that indicates whether the indexer pre-filters events. For real-time searches.
rt_maxblocksecs = 0 #The number of seconds indicating the maximum time to block. 0 means no limit. For real-time searches with "rt_blocking" set to "true".
rt_queue_size = 50000 #The number indicating the queue size (in events) that the indexer should use for this search. For real-time searches.
search_listener = "" #A string that registers a search state listener with the search. Use the format: search_state;results_condition;http_method;uri;
search_mode = "normal" #An enum value that indicates the search mode ("normal" or "realtime"). If set to "realtime", searches live data. A real-time search is also specified by setting "earliest_time" and "latest_time" parameters to "rt", even if the search_mode is normal or is not set.
spawn_process = False #A Boolean that indicates whether to run the search in a separate spawned process. Searches against indexes must run in a separate process.
status_buckets = 0 #The maximum number of status buckets to generate. 0 means to not generate timeline information.
sync_bundle_replication = True #A Boolean that indicates whether this search should wait for bundle replication to complete.
time_format = "%a %Y/%m/%d %T %Z %z" #EX:Sun 2015/07/26 14:02:03:001 CST [-0600] A string that specifies the format to use to convert a formatted time string from {start,end}_time into UTC seconds
timeout = 86400 #86400 = 24 HOURS The number of seconds to keep this search after processing has stopped.


# Run an export search and display the results using the results reader.

kwargs_export = {"auto_cancel": auto_cancel,
                 "auto_finalize_ec" : auto_finalize_ec,
                 "auto_pause" : auto_pause,
                 "earliest_time" : earliest_time,
                 "enable_lookups" : enable_lookups,
                 "exec_mode" : exec_mode,
                 "force_bundle_replication" : force_bundle_replication,
                 "id" : _id,
                 "index_earliest" : index_earliest,
                 "index_latest" : index_latest,
                 "latest_time" : latest_time,
                 "max_count" : max_count,
                 "max_time" : max_time,
                 "namespace" : namespace,
                 "now" : now,
                 "reduce_freq" : reduce_freq,
                 "reload_macros" : reload_macros,
                 "remote_server_list" : remote_server_list,
                 "rf" : rf,
                 "rt_blocking" : rt_blocking,
                 "rt_indexfilter" : rt_indexfilter,
                 "rt_maxblocksecs" : rt_maxblocksecs,
                 "rt_queue_size" : rt_queue_size,
                 "search_listener" : search_listener,
                 "search_mode" : search_mode,
                 "spawn_process" : spawn_process,
                 "status_buckets" : status_buckets,
                 "sync_bundle_replication" : sync_bundle_replication,
                 "time_format" : time_format,
                 "timeout" : timeout}


#get the current working directory
scripts_path = os.getcwd()
print (scripts_path)
scripts_path = scripts_path+"\\Queries"" #the query files should be placed in this directory which is inside the same directory this script will run from
print (scripts_path)
file_name_list = os.listdir(scripts_path)
lst_file_name_w_path = list()

for i in range(len(file_name_list)):
    filename = os.path.join(scripts_path,file_name_list[i] )
    lst_file_name_w_path.append(filename)

#each file in the Queries directory is a query that needs to be run
for i in range(len(lst_file_name_w_path)):
    nextfile = lst_file_name_w_path[i]
    with open(nextfile,"r") as fin:
        freader = csv.reader(fin, delimiter =",")
        data = list(freader)
        for line in fin:
            line.strip("\n\t\r")
            search = d[0][1] #the query string should be the first line in every file
            setting = str(d[i][0]).strip()#this is the same as the key in the disctionary
            value = d[i][1]
            if setting in default_settings:
                kwargs_export[setting] = value


searchquery_export = search
exportsearch_results = service.jobs.export(searchquery_export, **kwargs_export)


# Get the results and display them using the ResultsReader
qreader = results.ResultsReader(exportsearch_results)
for result in qreader:
    if isinstance(result, dict):
        print ("Result: %s" % result)
    elif isinstance(result, results.Message):
        # Diagnostic messages may be returned in the results
        print ("Message: %s" % result)

# Print whether results are a preview from a running search
print ("is_preview = %s " % reader.is_preview)
