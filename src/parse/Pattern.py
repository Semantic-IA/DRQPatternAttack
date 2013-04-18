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
    
    No parameters or return values, all info is read from the config and written to the database.
    """
    # FIXME: Add verification of file format, plus exception in case of violation
    # TODO: Also create a dictionary to list all patterns by length, for the pattern-based DRQ Generator
    if not Config.QUIET:
        stdout.write("Beginning parsing of pattern file... ")
        stdout.flush()
    for line in open(Config.INFILE, 'r'):               # Open the file for reading
        line = line.strip()                             # Remove trailing newlines
        target = line[:line.find(":")]                  # Find the target
        queries = line[line.find(":")+1:].split(",")    # Find the queries
        DB.PATTERNS[target] = set()                     # Add target and queries...
        for element in queries:                         # ...to both datasets in the DB
            if (element.find(":") > 0):
                element = element[:element.find(":")]   # Remove Port information, if any
            DB.QUERIES.add(element)                     # Add to set of all hostnames
            DB.PATTERNS[target].add(element)            # Add to current pattern
    if not Config.QUIET:
        print "Done"
    if(Config.VERBOSE):                                 # In case of verbose output, output some stats
        print "[V] Added " + str(len(DB.PATTERNS)) + " patterns."
        print "[V] " + str(len(DB.QUERIES)) + " Hostnames in Dataset."
        print "[V] That is an average of " + str(float(len(DB.QUERIES)) / len(DB.PATTERNS)) + " Queries per Pattern"