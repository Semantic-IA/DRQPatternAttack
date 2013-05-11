'''
DRQ Generator

Generates Range Queries for a given Domain and the corresponding pattern.
Divided into multiple classes. Each class provides a generateDRQFor(domain)-Function, but they will return their
results in different formats.

@author: Max Maass
'''
from random import shuffle
from data import DB
from var import Config

class BasicRangeQuery():
    """Basic Range Query generators
    
    All basic generators inherit from this class and use the generator this class provides.
    They will then proceed to shape their return value according to the generating strategy
    """
    def generateBaseDRQ(self,domain):
        """Generator for Basic DNS Range Queries (randomly generated query sets)
        
        @param domain: Domain for which a DNS Range Query should be generated
        @return: List of Sets, in order, each set representing a query block"""
        pass

class PatternRangeQuery():
    """Pattern Based Range Query generators
    
    All pattern-based generators inherit from this blass and use the generator this class provides.
    They will then proceed to shape their return value according to the generating strategy.
    """
    def generateBaseDRQ(self,domain):
        """Generator for Pattern-Based DNS Range Queries (trying to fill the query blocks with patterns)
        
        @param domain: Domain for which a DNS Range Query should be generated
        @return: List of Sets, in order, each set representing a query block
        """
        pass

class category():
    """Category of Range Queries
    
    All category classes inherit from this class. Those classes order generators into their respective categories.
    If any meta-information about the sum of all those classes needs to be stored, it will be stored in the variables
    this class provides.
    """
    pass

class BRQ(category):
    class NDBRQ(BasicRangeQuery):
        """No distinguishable Blocks Range Query"""
        
        def generateDRQFor(self,domain):
            """Generate a Range Query for a given domain name.
            
            Returns a single set of queries.
            len(block) == (len(DB.PATTERNS[domain])-1) * Config.RQSIZE is NOT guaranteed (Meaning that the intersection
            between selected random queries per hostname in the pattern is not always empty), so 
            len(return_value) modulo Config.RQSIZE does not have to be zero.
            
            @param domain: The domain name for which a range query should be constructed
            @return: A set of queries
            @note: Compatible with NDBPattern
            """
            # TODO: Idea: Add boolean parameter which would guarantee len(query) % Config.RQSIZE == 0?
            query = set()
            for subquery in DB.PATTERNS[domain]:
                query.add(subquery)
                query.update(DB.chooseRandomHosts(Config.RQSIZE-1))
            return query
    
    class DFBRQ(BasicRangeQuery):
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
            @note: Compatible with DFBPattern
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
    
    class FDBRQ(BasicRangeQuery):
        """Fully distinguishable blocks range query"""
        def generateDRQFor(self,domain):
            """Generate a Range Query with fully distinguishable blocks, meaning that each block contains exactly one
            element of the pattern, and len(list_of_blocks) == len(pattern).
            
            Returned hostnames are unique within their respective blocks, but not guaranteed to be unique across multiple
            blocks.
            
            @param domain: The domain name for which a range query should be constructed
            @return: A list of sets, each set representing a query block with one element from the pattern and at most
                Config.RQSIZE-1 randomly chosen hosts (sometimes less due to the nature of the random choice function
                and the set data type eleminating duplicates). The target is guaranteed to be contained in the first
                block, the other blocks can be in any order.
            @note: Compatible with FDBPattern
            """
            head = [set()]
            query = []
            head[0].add(domain)
            head[0].update(DB.chooseRandomHosts(Config.RQSIZE-1))
            for subquery in DB.PATTERNS[domain]:
                if subquery != domain:
                    block = set()
                    block.add(subquery)
                    block.update(DB.chooseRandomHosts(Config.RQSIZE-1))
                    query.append(block)
            shuffle(query)
            head += query
            return head

class PBRQ(category):
    """Pattern-based range query"""
    # TODO: Idea: Pad using multiple patterns that sum into the correct amount (Problem: Choice betw. alternatives)
    #     If used: For written part, consider timing problems using this method
    # TODO: Idea: Add more blocks that are not relevant to the "real" query.
    #     Meaning: Pattern length 6 -> 8 Blocks, add another Pattern with a length of 2 to continue orig. Pattern.
    #     Return Blocks in steps of N Blocks for obfuscation.
    # TODO: Problem: Weighted Probabilities or completely random selection?
    #     Weighted: More unlikely patterns are easier to guess correctly, and those are usually the relevant patterns
    #     Random: More likely patterns are easier to guess correctly, but those are usually also less interesting
    class NDBRQ(PatternRangeQuery):
        """No distinguishable blocks range query"""
        def generateDRQFor(self,domain):
            """Generate a Range Query for a given domain name.
    
            Returns a single set of queries.
            len(block) == (len(DB.PATTERNS[domain])-1) * Config.RQSIZE is NOT guaranteed (Meaning that the intersection
            between selected random queries per hostname in the pattern is not always empty), so 
            len(return_value) modulo Config.RQSIZE does not have to be zero.
            
            @param domain: The domain name for which a range query should be constructed
            @return: A set of queries
            @note: Compatible with NDBPattern
            """
            pass
    
    class DFBRQ(PatternRangeQuery):
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
            @note: Compatible with DFBPattern
            """
            pass
        
    class FDBRQ(PatternRangeQuery):
        """Fully distinguishable blocks range query"""
        def generateDRQFor(self,domain):
            """Generate a Range Query with fully distinguishable blocks, meaning that each block contains exactly one
            element of the pattern, and len(list_of_blocks) == len(pattern).
            
            Returned hostnames are unique [in a fashion to be decided, see TODO below].
            
            @param domain: The domain name for which a range query should be constructed
            @return: A list of sets, each set representing a query block with one element from the pattern and at most
                Config.RQSIZE-1 semi-randomly chosen hosts (sometimes less due to the nature of the random choice function
                and the set data type eleminating duplicates).
            @note: Compatible with FDBPattern
            """
            # TODO: Check decisions for original FDBRQ function before implementing this
            pass