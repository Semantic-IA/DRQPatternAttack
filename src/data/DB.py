'''
Holds the Data parsed from the pattern file for use in other modules

@author: Max Maass
'''
from random import choice, sample
PATTERNS = {}
QUERIES = set()
SIZES = {}

# TODO: Implement and use GETter, SETter, IS instead of direct access to the vars
def getRandomTarget():
    """Choose random Host from the list of possible targets
    
    The List of possible targets is the set of keys of the PATTERNS Dictionary.
    
    @return: A Hostname for which a pattern is known, as a string
    """
    return choice(PATTERNS.keys())

def getRandomHosts(number):
    """Choose random Hostnames from the set of all known hostnames
    
    @param number: Number of Hostnames to return
    @return: A list of unique hostnames (as strings)
    """
    assert number > 0
    return sample(QUERIES, number)

def getRandomHostsByPatternLength(size,number):
    """Choose random Hostnames from the set of all Hostnames with a pattern with a specified length.
    
    @param size: The size of the pattern each hostname should have
    @param number: The number of Hostnames that should be returned
    @return: A list of unique Hostnames (as strings)
    
    @requires: number <= len(SIZES[size])
    """
    assert number <= getNumberOfHostsWithPatternLength(size)
    return sample(SIZES[size], number)

def getNumberOfHostsWithPatternLength(length):
    """Get the number of hosts with a particular pattern length
    
    @param length: Pattern length
    @return: Number of hosts with that pattern length
    """
    assert length > 0
    try:
        return len(SIZES[length])
    except KeyError:
        return 0

def isValidTarget(host):
    """Check if the provided hostname is a valid target (meaning a pattern exists for it).
    
    @param host: The hostname
    @return: True or False
    """
    return host in PATTERNS.keys()

def getPatternForHost(host):
    """Get the Pattern for the provided hostname
    
    @param host: Hostname
    @return: A reference to the Pattern in the Pattern DB (a set)
    """
    assert isValidTarget(host)
    return PATTERNS[host]