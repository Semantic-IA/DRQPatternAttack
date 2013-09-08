'''
Holds the Data parsed from the pattern file for use in other modules

@author: Max Maass
'''
from random import choice, sample
from util import Error
PATTERNS = {}
QUERIES = set()
SIZES = {}
LENGTH = {}
# Formats of the dictionaries:
# PATTERNS[target_domain] = Pattern_as_list
# QUERIES = set(all_known_queries)
# SIZES[length] = list_of_domains_with_pattern_length
# LENGTH[domain] = length_of_domain_pattern

def getRandomTarget(database=PATTERNS):
    """Choose random Host from the list of possible targets

    The List of possible targets is the set of keys of the PATTERNS Dictionary.

    @param database: The database to be used.
    @return: A Hostname for which a pattern is known, as a string
    """
    return choice(database.keys())


def getRandomHosts(number, database=QUERIES):
    """Choose random Hostnames from the set of all known hostnames

    @param number: Number of Hostnames to return
    @param database: The database to be used.
    @return: A list of unique hostnames (as strings)
    """
    if not number > 0:
        Error.printErrorAndExit("getRandomHosts: number must be > 0, was " + str(number))
    return sample(database, number)


def getRandomHostsByPatternLengthB(size, number, blacklist=set([]), database=SIZES):
    """Choose random Hostnames from the set of all Hostnames with a pattern with a specified length, excluding a Blacklist.

    @param size: The size of the pattern each hostname should have
    @param number: The number of Hostnames that should be returned
    @param blacklist: A set of Domain Names that should not be considered when drawing the random hosts
    @param database: The database to be used.
    @return: A list of unique Hostnames (as strings)

    @requires: number <= len(SIZES[size]-blacklist)
    """
    if not number <= getNumberOfHostsWithPatternLengthB(size, blacklist, database):
        Error.printErrorAndExit("getRandomHostsByPatternLength: number must be <= number of available patterns, was " + str(number) + "/" + str(getNumberOfHostsWithPatternLengthB(size, blacklist)))
    return sample(database[size] - blacklist, number)

def getRandomHostsByPatternLength(size, number, database=SIZES):
    """Choose random Hostnames from the set of all Hostnames with a pattern with a specified length.

    @param size: The size of the pattern each hostname should have
    @param number: The number of Hostnames that should be returned
    @param database: The database to be used.
    @return: A list of unique Hostnames (as strings)

    @requires: number <= len(SIZES[size])
    """
    if not number <= getNumberOfHostsWithPatternLength(size, database):
        Error.printErrorAndExit("getRandomHostsByPatternLength: number must be <= number of available patterns, was " + str(number) + "/" + str(getNumberOfHostsWithPatternLength(size)))
    return sample(database[size], number)


def getNumberOfHostsWithPatternLengthB(length, blacklist=set([]), database=SIZES):
    """Get the number of hosts with a particular pattern length, excluding a Blacklist

    @param length: Pattern length
    @param blacklist: Set of Hostnames that should not be considered
    @param database: The database to be used.
    @return: Number of hosts with that pattern length
    """
    if not length > 0:
        Error.printErrorAndExit("getNumberOfHostsWithPatternLengthB: length must be > 0, was " + str(length))
    try:
        return len(database[length] - blacklist)
    except KeyError:
        return 0

def getNumberOfHostsWithPatternLength(length, database=SIZES):
    """Get the number of hosts with a particular pattern length

    @param length: Pattern length
    @param database: The database to be used.
    @return: Number of hosts with that pattern length
    """
    if not length > 0:
        Error.printErrorAndExit("getNumberOfHostsWithPatternLength: length must be > 0, was " + str(length))
    try:
        return len(database[length])
    except KeyError:
        return 0

def isValidTarget(host):
    """Check if the provided hostname is a valid target (meaning a pattern exists for it).

    @param host: The hostname
    @return: True (if the target is valid) or False (otherwise)
    """
    try:
        PATTERNS[host]
        return True
    except KeyError:
        return False


def getPatternForHost(host):
    """Get the Pattern for the provided hostname

    @param host: Hostname
    @return: A reference to the Pattern in the Pattern DB (a set)
    """
    if not isValidTarget(host):
        Error.printErrorAndExit("getPatternForHost: Invalid host " + str(host))
    return PATTERNS[host].copy()


def getPatternLengthForHost(host):
    """Get the length of the pattern for the provided hostname

    @param host: Hostname
    @return: Length of the Pattern
    """
    if not isValidTarget(host):
        Error.printErrorAndExit("getPatternLengthForHost: Invalid host " + str(host))
    return LENGTH[host]


def getAllPossibleTargets(database=PATTERNS):
    """Get a list of all targets that have a pattern associated with them

    @param database: The database to be used.
    @return: List of targets
    """
    return database.keys()


def getAllTargetsWithLength(length, database=SIZES):
    """Get a list of all targets whose patterns have a specific length

    @param length: The length
    @param database: The database to be used.
    @return: A list of possible Targets
    """
    if not length > 0:
        Error.printErrorAndExit("getAllTargetsWithLength: length must be > 0, was " + str(length))
    try:
        return list(database[length])
    except KeyError:
        return []


def addTarget(target, pattern):
    """Add a new target to the dictionary of targets.

    @param target: hostname of the target (String)
    @param pattern: query pattern (set)
    """
    # TODO: Convert asserts into if-blocks w/ Error.printErrorAndExit if something is wrong
    assert target != ""                 # Target not empty
    assert pattern != set([])           # Pattern not empty
    assert not isValidTarget(target)    # Target does not exist yet
    PATTERNS[target] = pattern
    length = len(pattern)
    try:
        SIZES[length].add(target)
    except KeyError:
        SIZES[length] = set([target])
    LENGTH[target] = length
    QUERIES.update(pattern)
    return
