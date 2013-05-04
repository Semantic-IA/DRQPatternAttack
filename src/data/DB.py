'''
Holds the Data parsed from the pattern file for use in other modules

@author: Max Maass
'''
from random import choice, sample
PATTERNS = {}
QUERIES = set()
SIZES = {}
# TODO: Verify that chooseRandom{Target,Hosts} works on Sets
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