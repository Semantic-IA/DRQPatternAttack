'''
Holds the Data parsed from the pattern file for use in other modules

@author: Max Maass
'''
from random import choice, sample
PATTERNS = {}
QUERIES = set()
SIZES = {}

def chooseRandomTarget():
    """Choose random Host from the list of possible targets
    
    The List of possible targets is the set of keys of the PATTERNS Dictionary.
    
    @return: A Hostname for which a pattern is known, as a string
    """
    return choice(PATTERNS.keys())

def chooseRandomHosts(number):
    """Choose random Hostnames from the set of all known hostnames
    
    @param number: Number of Hostnames to return
    @return: A list of unique hostnames (as strings)
    """
    return sample(QUERIES, number)

def chooseRandomHostsByPatternLength(size,number):
    """Choose random Hostnames from the set of all Hostnames with a pattern with a specified length.
    
    @param size: The size of the pattern each hostname should have
    @param number: The number of Hostnames that should be returned
    @return: A list of unique Hostnames (as strings)
    
    @requires: number <= len(SIZES[size])
    """
    assert number <= len(SIZES[size])
    return sample(SIZES[size], number)