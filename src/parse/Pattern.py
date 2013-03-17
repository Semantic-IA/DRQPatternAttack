'''
Pattern File Parser

Parses a pattern file and saves the content in a data structure for later use by other modules.

@author: Max Maass
'''
from var import Config  # Configuration Variables
from data import DB     # Database to save the parsed Patterns
from sys import stdout  # For nicer status reports

def parse():
    """Parses the INFILE
    INFILE is expected to have a format of:
    target.tld:query1.tld,query2.tld,query3.tld,...
    """
    # @TODO: Add verification of file format, plus exception in case of violation
    stdout.write("Beginning parsing of pattern file... ")
    stdout.flush()
    for line in open(Config.INFILE, 'r'):               # Open the file for reading
        line = line.strip()                             # Remove trailing newlines
        target = line[:line.find(":")]                  # Find the target
        queries = line[line.find(":")+1:].split(",")    # Find the queries
        DB.PATTERNS[target] = []                        # Add target and queries...
        for element in queries:                         # ...to both datasets in the DB
            if (element.find(":") > 0):
                element = element[:element.find(":")]   # Remove Port information, if any
            DB.QUERIES.add(element)                     # Add to set of all hostnames
            DB.PATTERNS[target].append(element)         # Add to current pattern
    print "Done"
    if(Config.VERBOSE):                                 # In case of verbose output, give some stats
        print "[V] Added " + str(len(DB.PATTERNS)) + " patterns."
        print "[V] " + str(len(DB.QUERIES)) + " Hostnames in Dataset."
        print "[V] That is an average of " + str(float(len(DB.QUERIES)) / len(DB.PATTERNS)) + " Queries per Pattern"