'''
Pattern File Parser

Parses a pattern file and saves the content in a data structure for later use by other modules.

@author: Max Maass
'''
from var import Config  # Configuration Variables
from data import DB     # Database to save the parsed Patterns

def parse():
    for line in open(Config.INFILE, 'r'):
        target = line[:line.find(":")]
        queries = line[line.find(":")+1:].split(",")
        DB.PATTERNS[target] = queries
        for element in queries:
            DB.QUERIES.add(element)
    