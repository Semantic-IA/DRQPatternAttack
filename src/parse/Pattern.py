'''
Pattern File Parser

Parses a pattern file and saves the content in a data structure for later use by other modules.

@author: Max Maass
'''
from var import Config  # Configuration Variables
from data import DB     # Database to save the parsed Patterns
from sys import stdout  # For nicer status reports
from output import Progress

def parse():
    """Parses the INFILE
    INFILE is expected to have a format of:
    target.tld:query1.tld,query2.tld,query3.tld,...
    
    No parameters or return values, all info is read from the config and written to the database.
    @bug: Leading www. in domain name may cause issues if the www. is omitted in the pattern
    """
    # FIXME: Add verification of file format, plus exception in case of violation
    # FIXME: Known Issue: leading www. in domain name
    if not Config.QUIET:
        print("Beginning parsing of pattern file... ")
    LC = 0
    with open(Config.INFILE, 'r') as fobj:
        LC = sum(1 for line in fobj)
    stat = Progress.Bar(LC,"=")
    for line in open(Config.INFILE, 'r'):               # Open the file for reading
        line = line.strip()                             # Remove trailing newlines
        target = line[:line.find(":")]                  # Find the target
        queries = line[line.find(":")+1:].split(",")    # Find the queries
        DB.PATTERNS[target] = set()                     # Add target and queries...
        for element in queries:                         # ...and to both datasets in the DB
            if (element.find(":") > 0):
                element = element[:element.find(":")]   # Remove Port information, if any
            DB.QUERIES.add(element)                     # Add to set of all hostnames
            DB.PATTERNS[target].add(element)            # Add to current pattern
        try:
            DB.SIZES[len(DB.PATTERNS[target])].append(target)
        except KeyError:
            DB.SIZES[len(DB.PATTERNS[target])] = [target]
        stat.tick()
    if not Config.QUIET:
        print "Done"
    if Config.VERBOSE:                                 # In case of verbose output, output some stats
        print "[V] Added " + str(len(DB.PATTERNS)) + " patterns."
        print "[V] " + str(len(DB.QUERIES)) + " Hostnames in Dataset."
        print "[V] That is an average of " + str(float(len(DB.QUERIES)) / len(DB.PATTERNS)) + " Queries per Pattern"