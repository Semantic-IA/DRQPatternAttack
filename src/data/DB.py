'''
Holds the Data parsed from the pattern file for use in other modules

@author: Max Maass
'''
from random import choice, sample
PATTERNS = {}
QUERIES = set()
# TODO: Verify that chooseRandom{Target,Hosts} works on Sets
def chooseRandomTarget():
    return choice(PATTERNS.keys())

def chooseRandomHosts(number):
    return sample(QUERIES, number)