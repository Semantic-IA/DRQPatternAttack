'''
Pattern File Parser

Parses a pattern file and saves the content in a data structure for later use by other modules.

@author: Max Maass
'''
from var import Config  # Configuration Variables
from data import DB     # Database to save the parsed Patterns
from sys import stdout

def parse():
    """Parses the INFILE
    INFILE is expected to have a format of:
    target.tld:query1.tld,query2.tld,query3.tld,...
    """
    # @TODO: Add verification of file format, plus exception in case of violation
    if(Config.VERBOSE):
        stdout.write("PARSER: Beginning parsing of pattern file... ")
        stdout.flush()
    for line in open(Config.INFILE, 'r'):               # Open the file for reading
        target = line[:line.find(":")]                  # Find the target
        queries = line[line.find(":")+1:].split(",")    # Find the queries
        DB.PATTERNS[target] = queries                   # Add target and queries...
        for element in queries:                         # ...to both datasets in the DB
            DB.QUERIES.add(element)
    if(Config.VERBOSE):                                 # In case of verbose output, give some stats
        print "Done"
        print "PARSER: Added " + str(len(DB.PATTERNS)) + " patterns."
        print "PARSER: " + str(len(DB.QUERIES)) + " Hostnames in Dataset."
        print "PARSER: That is an average of " + str(float(len(DB.QUERIES)) / len(DB.PATTERNS)) + " Queries per Pattern"