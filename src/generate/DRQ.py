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
    @return: A set of queries
    """
    # TODO: Check this function after defining the exact RQ Algorithm
    query = []
    for subquery in DB.PATTERNS[domain]:
        query.append(subquery)
        query.extend(DB.chooseRandomHosts(Config.RQSIZE-1))
    return set(query)

def generateDDRQFor(domain):
    """Generate a Range Query with a distinguishable first query block.
    
    @param domain: The domain name for which a range query should be constructed
    @return: A tuple of two sets, the first containing the first query block, the second containing the remaining queries
    """
    head = set()    # First Set of Queries
    block = set()   # Remaining Queries
    head.add(domain)
    head.update(DB.chooseRandomHosts(Config.RQSIZE-1))
    for subquery in DB.PATTERNS[domain]:
        if subquery != domain:
            block.add(subquery)
            block.update(DB.chooseRandomHosts(Config.RQSIZE-1))
    return (head, block)