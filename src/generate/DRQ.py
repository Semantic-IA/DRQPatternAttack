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
from util import Error
from itertools import cycle


class BasicRangeQuery(object):
    """Basic Range Query generators

    All basic generators inherit from this class and use the generator this class provides.
    They will then proceed to shape their return value according to the generating strategy
    """

    def generateBaseDRQ(self, domain):
        """Generator for Basic DNS Range Queries (randomly generated query sets)

        Queries are unique inside their respective sets, but may appear more than once across different
        query blocks.

        @param domain: Domain for which a DNS Range Query should be generated
        @return: List of Sets, in order, each set representing a query block
        """
        if not DB.isValidTarget(domain):
            Error.printErrorAndExit(domain + " is not a valid target")
        patlen = DB.getPatternLengthForHost(domain)
        block = [set()]
        pattern = DB.getPatternForHost(domain)
        randoms = DB.getRandomHosts((Config.RQSIZE-1)*len(pattern))
        pattern.remove(domain)
        block[0].add(domain)
        i = 1
        for subquery in pattern:
            block.append(set())
            block[i].add(subquery)
            i += 1
        for query, index in zip(randoms, cycle(range(patlen))):
            block[index].add(query)
        return block


class PatternRangeQuery(object):
    """Pattern Based Range Query generators

    All pattern-based generators inherit from this class and use the generator this class provides.
    They will then proceed to shape their return value according to the generating strategy.
    """

    def generateBaseDRQ(self, domain):
        """Generator for Pattern-Based DNS Range Queries (trying to fill the query blocks with patterns)

        Queries are unique inside their respective sets, but may appear more than once across different
        query blocks.

        @param domain: Domain for which a DNS Range Query should be generated
        @return: List of Sets, in order, each set representing a query block
        """
        if not DB.isValidTarget(domain):
            Error.printErrorAndExit(domain + " is not a valid target")
        pattern_length = len(DB.PATTERNS[domain])
        block = [set()]
        num_of_available_patterns = DB.getNumberOfHostsWithPatternLength(pattern_length) - 1
        if num_of_available_patterns >= Config.RQSIZE:
            hosts = set([domain])
            hosts.update(set(DB.getRandomHostsByPatternLengthB(pattern_length, Config.RQSIZE-1, hosts)))
            pattern_copy = {}
            for host in hosts:
                pattern_copy[host] = DB.getPatternForHost(host)
                pattern_copy[host].remove(host) 
                block[0].add(host)
            for i in range(1, pattern_length, 1):
                block.append(set())
                for host in pattern_copy:
                    block[i].add(pattern_copy[host].pop())
        else: 
            num_of_needed_patterns = Config.RQSIZE - (num_of_available_patterns+1)
            padding = []
            for i in range(num_of_needed_patterns):
                # Find patterns whose lengths sum to pattern_length (if any exist that have not been chosen yet)
                pad1_len = pad2_len = -1
                for pad1_len, pad2_len in zip(range(1, pattern_length/2+1, 1), range(pattern_length-1, pattern_length/2-1, -1)):
                    if ((DB.getNumberOfHostsWithPatternLengthB(pad1_len, block[0]) > 0) and \
                        (DB.getNumberOfHostsWithPatternLength(pad2_len) > 0)):
                        break
                    elif pad1_len == pattern_length/2: # No fitting patterns have been found, abort
                        pad1_len = -1
                if (pad1_len == -1): # Break out of loop as no further patterns can be found.
                    break
                pad1_host = DB.getRandomHostsByPatternLengthB(pad1_len, 1, block[0])[0]
                pad1_pattern = DB.getPatternForHost(pad1_host)
                pad1_pattern.remove(pad1_host)
                block[0].add(pad1_host)
                padding.append([pad1_host])
                for host in pad1_pattern:
                    padding[i].append(host)
                pad2_host = DB.getRandomHostsByPatternLength(pad2_len, 1)[0]
                pad2_pattern = DB.getPatternForHost(pad2_host)
                pad2_pattern.remove(pad2_host)
                padding[i].append(pad2_host)
                for host in pad2_pattern:
                    padding[i].append(host)
            pattern_copy = {}
            block[0].add(domain)
            pattern_copy[domain] = DB.getPatternForHost(domain)
            pattern_copy[domain].remove(domain)
            for element in DB.getRandomHostsByPatternLengthB(pattern_length, num_of_available_patterns, block[0]):
                pattern_copy[element] = DB.getPatternForHost(element)
                pattern_copy[element].remove(element)
                block[0].add(element)
            for i in range(1, pattern_length, 1):
                block.append(set())
                for host in pattern_copy:
                    block[i].add(pattern_copy[host].pop())
                for pattern in padding:
                    block[i].add(pattern[i])
        return block


class Category(object):
    """Category of Range Queries

    All category classes inherit from this class. Those classes order generators into their respective categories.
    If any meta-information about the sum of all those classes needs to be stored, it will be stored in the variables
    this class provides.
    """
    pass


class BRQ(Category):
    class NDBRQ(BasicRangeQuery):
        """No distinguishable Blocks Range Query"""

        def generateDRQFor(self, domain):
            """Generate a Range Query for a given domain name.

            Returns a single set of queries.
            len(block) == (len(DB.PATTERNS[domain])-1) * Config.RQSIZE is NOT guaranteed (Meaning that the intersection
            between selected random queries per hostname in the pattern is not always empty), so
            len(return_value) modulo Config.RQSIZE does not have to be zero.

            @param domain: The domain name for which a range query should be constructed
            @return: A set of queries
            @note: Compatible with NDBPattern
            """
            block = BasicRangeQuery.generateBaseDRQ(self, domain)
            query = set()
            for set_of_queries in block:
                query.update(set_of_queries)
            return query


    class DFBRQ(BasicRangeQuery):
        """Distinguishable first Block Range Query"""
        def generateDRQFor(self, domain):
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
            block = BasicRangeQuery.generateBaseDRQ(self, domain)
            head = block[0]    # First Set of Queries
            tail = set()       # Remaining Queries
            for set_of_queries in block[1:]:  # Add all elements from the tailing query blocks to big query block
                tail.update(set_of_queries)
            return (head, tail)


    class FDBRQ(BasicRangeQuery):
        """Fully distinguishable blocks range query"""
        def generateDRQFor(self, domain):
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
            block = BasicRangeQuery.generateBaseDRQ(self, domain)
            head = [block[0]]
            tail = block[1:]
            shuffle(tail)
            block = head + tail
            return block


class PBRQ(Category):
    """Pattern-based range query"""
    class NDBRQ(PatternRangeQuery):
        """No distinguishable blocks range query"""
        def generateDRQFor(self, domain):
            """Generate a Range Query for a given domain name.

            Returns a single set of queries.
            len(block) == (len(DB.PATTERNS[domain])-1) * Config.RQSIZE is NOT guaranteed (Meaning that the intersection
            between selected random queries per hostname in the pattern is not always empty), so
            len(return_value) modulo Config.RQSIZE does not have to be zero.

            @param domain: The domain name for which a range query should be constructed
            @return: A set of queries
            @note: Compatible with NDBPattern
            """
            block = PatternRangeQuery.generateBaseDRQ(self, domain)
            query = set()
            for set_of_queries in block:
                query.update(set_of_queries)
            return query


    class DFBRQ(PatternRangeQuery):
        """Distinguishable first block range query"""
        def generateDRQFor(self, domain):
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
            block = PatternRangeQuery.generateBaseDRQ(self, domain)
            head = block[0]    # First Set of Queries
            tail = set()       # Remaining Queries
            for set_of_queries in block[1:]:  # Add all elements from the tailing query blocks to big query block
                tail.update(set_of_queries)
            return (head, tail)


    class FDBRQ(PatternRangeQuery):
        """Fully distinguishable blocks range query"""
        def generateDRQFor(self, domain):
            """Generate a Range Query with fully distinguishable blocks, meaning that each block contains exactly one
            element of the pattern, and len(list_of_blocks) == len(pattern).

            Returned hostnames are unique within their respective blocks, but not guaranteed to be unique across multiple
            blocks.

            @param domain: The domain name for which a range query should be constructed
            @return: A list of sets, each set representing a query block with one element from the pattern and at most
                Config.RQSIZE-1 semi-randomly chosen hosts (sometimes less due to the nature of the random choice function
                and the set data type eleminating duplicates).
            @note: Compatible with FDBPattern
            """
            block = PatternRangeQuery.generateBaseDRQ(self, domain)
            head = [block[0]]
            tail = block[1:]
            shuffle(tail)
            block = head + tail
            return block