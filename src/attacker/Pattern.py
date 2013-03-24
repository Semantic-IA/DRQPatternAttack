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
        @return: TBD"""
        # TODO: Think about return format
        res = []
        for key in DB.PATTERNS.keys():
            inter = intersection(rq,DB.PATTERNS[key])
            if len(inter) == len(DB.PATTERNS[key]) and not len(rq) % len(inter):
                res.append(key)
        return res
                