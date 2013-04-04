'''
Main Attacker Module

Implements different versions of the Attack. See Class Documentation for further information

@author: Max Maass
'''
from data import DB
def intersection(a, b):
    return list(set(a) & set(b))

class patternV1():
    def attack(self,rq):
        """Attack a given Range Query
        
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
    """Distinguishable First Block Pattern Attack"""
    
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