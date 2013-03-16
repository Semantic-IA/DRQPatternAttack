'''
Holds the Data parsed from the pattern file for use in other modules

@author: Max Maass
'''
from random import choice, sample
PATTERNS = {}
QUERIES = set()

def chooseRandomTarget():
    return choice(PATTERNS.keys())

def chooseRandomHosts(number):
    return sample(QUERIES, number)