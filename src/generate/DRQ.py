'''
DRQ Generator

Generates Range Queries for a given Domain and the corresponding pattern.
Divided into multiple classes. Each class provides a generateDRQFor(domain)-Function, but they will return their
results in different formats.

@author: Max Maass
'''
from data import DB
from var import Config
# TODO: Add @note: Compatible with ... to all functions.
class UBRQ():
    """Undistinguishable Blocks Range Query"""
    
    def generateDRQFor(self,domain):
        """Generate a Range Query for a given domain name.
        
        Returns a single set of queries.
        len(block) == (len(DB.PATTERNS[domain])-1) * Config.RQSIZE is NOT guaranteed (Meaning that the intersection
        between selected random queries per hostname in the pattern is not always empty), so 
        len(return_value) modulo Config.RQSIZE does not have to be zero.
        
        @param domain: The domain name for which a range query should be constructed
        @return: A set of queries
        @note: Compatible with [...]
        """
        # TODO: Idea: Add boolean parameter which would guarantee len(query) % Config.RQSIZE == 0?
        query = []
        for subquery in DB.PATTERNS[domain]:
            query.append(subquery)
            query.extend(DB.chooseRandomHosts(Config.RQSIZE-1))
        return set(query)

class DFBRQ():
    """Distinguishable first Block Range Query"""
    def generateDRQFor(self,domain):
        """Generate a Range Query with a distinguishable first query block.
        
        Returned hostnames are unique inside their respective sets, but len(head + block) = len(head) + len(block) is NOT
        guaranteed (meaning that a single hostname can be in both sets).
        len(block) == (len(DB.PATTERNS[domain])-1) * Config.RQSIZE is also NOT guaranteed (Meaning that the intersection
        between selected random queries per hostname in the pattern is not always empty)
        
        @param domain: The domain name for which a range query should be constructed
        @return: A tuple of two sets, the first containing the first query block, the second containing the remaining 
            queries
        @note: Compatible with [...]
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

class FDBRQ():
    """Fully distinguishable blocks range query"""
    def generateDRQFor(self,domain):
        """Generate a Range Query with fully distinguishable blocks, meaning that each block contains exactly one
        element of the pattern, and len(list_of_blocks) == len(pattern).
        
        Returned hostnames are unique [in a fashion to be decided, see TODO below].
        
        @param domain: The domain name for which a range query should be constructed
        @return: A list of sets, each set representing a query block with one element from the pattern and at most
            Config.RQSIZE-1 randomly chosen hosts (sometimes less due to the nature of the random choice function
            and the set data type eleminating duplicates).
        @note: Compatible with [...]
        """
        # TODO: Decide: Which uniqueness method should be used: Unique inside blocks, unique across all blocks?
        # TODO: Decide: Blocks in Order? First block in order, remaining blocks in random order? Add. Parameter?
        pass

class PBRQ():
    """Pattern-based range query"""
    # TODO: Consider: All implemented methods could be re-implemented with pattern-based generation
    #     Pos. Solution: Subclasses?
    # TODO: Idea: Pad using multiple patterns that sum into the correct amount (Problem: Choice btw. alternatives)
    #     If used: For written part, consider timing problems using this method
    class UBRQ():
        """Undistinguishable blocks range query"""
        def generateDRQFor(self,domain):
            """Generate a Range Query for a given domain name.
    
            Returns a single set of queries.
            len(block) == (len(DB.PATTERNS[domain])-1) * Config.RQSIZE is NOT guaranteed (Meaning that the intersection
            between selected random queries per hostname in the pattern is not always empty), so 
            len(return_value) modulo Config.RQSIZE does not have to be zero.
            
            @param domain: The domain name for which a range query should be constructed
            @return: A set of queries
            @note: Compatible with [...]
            """
            pass
    
    class DFBRQ():
        """Distinguishable first block range query"""
        def generateDRQFor(self,domain):
            """Generate a Range Query with a distinguishable first query block.
        
            Returned hostnames are unique inside their respective sets, but len(head + block) = len(head) + len(block) is NOT
            guaranteed (meaning that a single hostname can be in both sets).
            len(block) == (len(DB.PATTERNS[domain])-1) * Config.RQSIZE is also NOT guaranteed (Meaning that the intersection
            between selected random queries per hostname in the pattern is not always empty)
            
            @param domain: The domain name for which a range query should be constructed
            @return: A tuple of two sets, the first containing the first query block, the second containing the remaining 
                queries
            @note: Compatible with [...]
            """
            pass
        
    class FDBRQ():
        """Fully distinguishable blocks range query"""
        def generateDRQFor(self,domain):
            """Generate a Range Query with fully distinguishable blocks, meaning that each block contains exactly one
            element of the pattern, and len(list_of_blocks) == len(pattern).
            
            Returned hostnames are unique [in a fashion to be decided, see TODO below].
            
            @param domain: The domain name for which a range query should be constructed
            @return: A list of sets, each set representing a query block with one element from the pattern and at most
                Config.RQSIZE-1 semi-randomly chosen hosts (sometimes less due to the nature of the random choice function
                and the set data type eleminating duplicates).
            @note: Compatible with [...]
            """
            # TODO: Check decisions for original FDBRQ function before implementing this
            pass