'''
Main Attacker Module

Implements different versions of the Attack. See Class Documentations for further information.

Each class provides at least one function, 'attack', which is used to run a simulated attack on the provided data.
The attack functions take different inputs, but will always return a list of possible results.

@author: Max Maass
'''

# TODO: Idea: Restructure this into classes to mirror the classes of the generators.
# TODO: Check: Mathing naming conventions for generators and attackers
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
    
    def attack(self,block):
        """Attack a given Range Query with a distinguishable first block
        
        @param fb: The first block, as set
        @param rq: The remaining range query, as set
        @return: List of possible results
        """
        fb, rq = block
        res = []
        rq.update(fb)
        for key in DB.PATTERNS.keys():
            if key in fb:
                if DB.PATTERNS[key] <= rq:
                    res.append(key)
        return res

class FDBPattern():
    """Fully distinguishable Blocks pattern Attack
    
    This attack assumes that all blocks are distinguishable. Each block contains exactly one part of the pattern.
    Depending on the implementation of the real life DRQ generator, this might be a valid assumption, but if some care
    is taken it should NOT be possible to distinguish the blocks (apart from the first block, which is pretty much
    unavoidable)
    """
    
    def attack(self,blocklist):
        """Attack a given range query with fully distinguishable blocks
        
        @param blocklist: A list of sets, each set representing a block, the main target in the first block.
        @return: List of possible results
        """
        res = []
        for key in DB.SIZES[len(blocklist)]:
            if key in blocklist[0]:
                tmp = blocklist[1:]
                cnt = {}
                for i in range(len(blocklist)-1):
                    cnt[i] = 0
                for query in DB.PATTERNS[key]:
                    if query != key:
                        for i in range(len(tmp)):
                            if query in tmp[i]:
                                cnt[i] += 1
                if not 0 in cnt.values():
                    res.append(key)
        return res