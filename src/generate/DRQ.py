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
    @return: A list of queries"""
    # TODO: Determine if return value should be list or set
    # TODO: Check this function after defining the exact RQ Algorithm
    query = []
    for subquery in DB.PATTERNS[domain]:
        query.append(subquery)
        query.extend(DB.chooseRandomHosts(Config.RQSIZE-1))
    return query