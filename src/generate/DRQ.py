'''
DRQ Generator

Generates Range Queries for a given Domain and the corresponding pattern

@author: Max Maass
'''
from data import DB
from var import Config

def generateDRQFor(domain):
    """Generate a Range Query for a given domain name.
    
    @param domain: The domain name for which a range query should be constructed
    @return: A set of queries"""
    # TODO: Verify functionality after change to set
    # TODO: Add check that the size requirements are met after transition to set
    # TODO: Check this function after defining the exact RQ Algorithm
    query = []
    for subquery in DB.PATTERNS[domain]:
        query.append(subquery)
        query.extend(DB.chooseRandomHosts(Config.RQSIZE-1))
    return set(query)