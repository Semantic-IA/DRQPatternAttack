'''
Main Attacker Module

Implements different versions of the Attack. See Class Documentations for further information.

Each class provides at least one function, 'attack', which is used to run a simulated attack on the provided data.
The attack functions take different inputs, but will always return a list of possible results.

@author: Max Maass
'''
from data import DB
import math


class NDBPattern():
    """No distinguishable blocks pattern attack

    This attack assumes that the blocks of queries cannot be distinguished and will arrive as a single block.
    This assumption is unrealistic, since followup queries of the pattern require resolution of the primary host to load
    the HTML of the requested site, which will only then trigger the following Queries. Nontheless, it is an assumption
    that enables us to test our algorithms against a scenario that approaches the worst case.
    """

    def attack(self, rq):
        """Attack a given Range Query using the assumption from the class description.

        @param rq: A Range Query, as returned by generate.DRQ
        @return: list of possible results
        """
        res = []
        for element in rq: # Iterate through all elements (queries) of the given range query
            if DB.isValidTarget(element): # If the current element is the beginning of a pattern...
                # This checks if the pattern of the current element is a subset of the range query
                inter = rq & DB.getPatternForHost(element) 
                if len(inter) == DB.getPatternLengthForHost(element):
                    res.append(element)
        return res


class DFBPatternBRQ():
    """Distinguishable First Block Pattern Attack for the basic (random) range query generation.

    This attack assumes that the first block of the queries can be distinguished from the following blocks, while
    all following blocks are indistinguishable from each other. This assumption is realistic for the reasons given in
    the description of the 'No distinguishable blocks pattern attack'.
    """

    def attack(self, block):
        """Attack a given Range Query with a distinguishable first block

        This function can only be used under specific circumstances, which is why it is not the default function.
        To use it, change the Dictionary of the getAttackerFor-function in DRQPatternAttack.py to point to
        DFBPatternBRQ instead of DFBPatternPRQ, but be aware that it will not always work on small data sets.

        @param fb: The first block, as set
        @param rq: The remaining range query, as set
        @return: List of possible results
        """
        fb, rq = block
        res = []
        suspected_n = float(len(fb))
        rq.update(fb)
        rqlen = len(rq)
        pattern_length_max = math.ceil(rqlen / suspected_n)
        pattern_length_max += math.ceil(pattern_length_max / suspected_n)
        pattern_length_max += math.ceil(pattern_length_max / suspected_n)
        # Increase maximum pattern length, because duplicates could lead to a miscalculation of up to floor(real_pattern_length/real_N).
        # We are using ceil() to avoid border cases where the real M would lead to x in that calculation, while our detected M
        # only leads to x-1. Those cases would be few and far between, considering the chances of actually getting so many duplicates,
        # but nevertheless, they should be dealt with.
        pattern_length_min = math.floor(rqlen / (suspected_n+1))
        for key in fb: # Iterate through all elements of the first block
            if DB.isValidTarget(key) and (pattern_length_min <= DB.getPatternLengthForHost(key) <= pattern_length_max):
                # if the current element is a beginning of a pattern with the correct length...
                if DB.getPatternForHost(key) <= rq: # Check if the pattern is a subset of the remaining range query.
                    res.append(key)
        return res


class DFBPatternPRQ():
    """Distinguishable First Block Pattern Attack for the pattern-based range query generation.

    This attack assumes that the first block of the queries can be distinguished from the following blocks, while
    all following blocks are indistinguishable from each other. This assumption is realistic for the reasons given in
    the description of the 'No distinguishable blocks pattern attack'.
    """

    def attack(self, block):
        """Attack a given Range Query with a distinguishable first block

        @param fb: The first block, as set
        @param rq: The remaining range query, as set
        @return: List of possible results
        """
        fb, rq = block
        res = []
        rq.update(fb)
        for key in fb: # Iterate through all queries in the first block
            if DB.isValidTarget(key): # If the current query is a valid beginning of a pattern...
                if DB.getPatternForHost(key) <= rq: # Check if the pattern is a subset of the second block.
                    res.append(key)
        return res


class FDBPattern():
    """Fully distinguishable Blocks pattern Attack

    This attack assumes that all blocks are distinguishable. Each block contains exactly one part of the pattern.
    Depending on the implementation of the real life DRQ generator, this might be a valid assumption, but if some care
    is taken it should NOT be possible to distinguish the blocks (apart from the first block, which is pretty much
    unavoidable)
    """

    def attack(self, blocklist):
        """Attack a given range query with fully distinguishable blocks

        @param blocklist: A list of sets, each set representing a block, the main target in the first block.
        @return: List of possible results
        """
        res = []
        length = len(blocklist)
        for key in blocklist[0]: # Iterate through all candidates for the main target (as it must be in the first block)
            if DB.isValidTarget(key) and DB.getPatternLengthForHost(key) == length: # If it is the beginning of a pattern of the correct length...
                # The following is a method of determining if every block contains exactly one element of the pattern of the current candidate.
                tmp = blocklist[1:]
                cnt = {}
                for i in range(length-1):
                    cnt[i] = 0
                for query in DB.getPatternForHost(key):
                    if query != key:
                        for i in range(len(tmp)):
                            if query in tmp[i]:
                                cnt[i] += 1
                if not 0 in cnt.values():
                    res.append(key)
        return res
