'''
DRQ Generator

Generates Range Queries for a given Domain and the corresponding pattern

@author: Max Maass
'''
from data import DB
from var import Config

def generateDRQFor(domain):
    """Generate a Range Query for a given domain name.
    
    Returns a single set of queries.
    len(block) == (len(DB.PATTERNS[domain])-1) * Config.RQSIZE is NOT guaranteed (Meaning that the intersection
    between selected random queries per hostname in the pattern is not always empty), so 
    len(return_value) modulo Config.RQSIZE does not have to be zero.
    
    @param domain: The domain name for which a range query should be constructed
    @return: A set of queries
    """
    # TODO: Check this function after defining the exact RQ Algorithm
    # TODO: Add boolean parameter which would guarantee len(query) % Config.RQSIZE == 0?
    query = []
    for subquery in DB.PATTERNS[domain]:
        query.append(subquery)
        query.extend(DB.chooseRandomHosts(Config.RQSIZE-1))
    return set(query)

def generateDDRQFor(domain):
    """Generate a Range Query with a distinguishable first query block.
    
    Returned hostnames are unique inside their respective sets, but len(head + block) = len(head) + len(block) is NOT
    guaranteed (meaning that a single hostname can be in both sets).
    len(block) == (len(DB.PATTERNS[domain])-1) * Config.RQSIZE is also NOT guaranteed (Meaning that the intersection
    between selected random queries per hostname in the pattern is not always empty)
    
    @param domain: The domain name for which a range query should be constructed
    @return: A tuple of two sets, the first containing the first query block, the second containing the remaining queries
    """
    # TODO: Add boolean parameter which would guarantee len(query) % Config.RQSIZE == 0?
    head = set()    # First Set of Queries
    block = set()   # Remaining Queries
    head.add(domain)
    head.update(DB.chooseRandomHosts(Config.RQSIZE-1))
    for subquery in DB.PATTERNS[domain]:
        if subquery != domain:
            block.add(subquery)
            block.update(DB.chooseRandomHosts(Config.RQSIZE-1))
    return (head, block)