'''
Main Attacker Module

Implements different versions of the Attack. See Class Documentations for further information.

Each class provides at least one function, 'attack', which is used to run a simulated attack on the provided data.

@author: Max Maass
'''
from data import DB
def intersection(a, b):
    return list(set(a) & set(b))

class NDBPattern():
    """No distinguishable blocks pattern attack
    
    This attack assumes that the blocks of queries cannot be distinguished and will arrive as a single block.
    This assumption is unrealistic, since followup queries of the pattern require resolution of the primary host to load
    the HTML of the requested site, which will only then trigger the following Queries. Nontheless, it is an assumption
    that enables us to test our algorithms against a scenario that approaches the worst case.
    """
    
    def attack(self,rq):
        """Attack a given Range Query using the assumption from the class description.
        
        @param rq: A Range Query, as returned by generate.DRQ
        @return: list of possible results
        """
        # TODO: Think about return format
        res = []
        for key in DB.PATTERNS.keys():
            inter = intersection(rq,DB.PATTERNS[key])
            if len(inter) == len(DB.PATTERNS[key]):
                res.append(key)
        return res
    
class DFBPattern():
    """Distinguishable First Block Pattern Attack
    
    This attack assumes that the first block of the queries can be distinguished from the following blocks, while 
    all following blocks are indistinguishable from each other. This assumption is realistic for the reasons given in
    the description of the 'No distinguishable blocks pattern attack'.
    """
    
    def attack(self,fb,rq):
        """Attack a given Range Query with a distinguishable first block
        
        @param fb: The first block, as set
        @param rq: The remaining range query, as set
        @return: List of possible results
        """
        res = []
        rq.update(fb)
        for key in DB.PATTERNS.keys():
            if key in fb:
                if DB.PATTERNS[key] <= rq:
                    res.append(key)
        return res

### Moegliche weitere Annahmen:
# Komplett unterscheidbare Bloecke