'''
Holds the Data parsed from the pattern file for use in other modules

@author: Max Maass
'''
from random import choice, sample
from util import Error
PATTERNS = {}
QUERIES = set()
SIZES = {}


def getRandomTarget():
    """Choose random Host from the list of possible targets

    The List of possible targets is the set of keys of the PATTERNS Dictionary.

    @return: A Hostname for which a pattern is known, as a string
    """
    return choice(PATTERNS.keys())


def getRandomHosts(number):
    """Choose random Hostnames from the set of all known hostnames

    @param number: Number of Hostnames to return
    @return: A list of unique hostnames (as strings)
    """
    if not number > 0:
        Error.printErrorAndExit("getRandomHosts: number must be > 0, was " + str(number))
    return sample(QUERIES, number)


def getRandomHostsByPatternLength(size, number):
    """Choose random Hostnames from the set of all Hostnames with a pattern with a specified length.

    @param size: The size of the pattern each hostname should have
    @param number: The number of Hostnames that should be returned
    @return: A list of unique Hostnames (as strings)

    @requires: number <= len(SIZES[size])
    """
    if not number <= getNumberOfHostsWithPatternLength(size):
        Error.printErrorAndExit("getRandomHostsByPatternLength: number must be <= number of available patterns, was " + str(number) + "/" + str(getNumberOfHostsWithPatternLength(size)))
    return sample(SIZES[size], number)


def getNumberOfHostsWithPatternLength(length):
    """Get the number of hosts with a particular pattern length

    @param length: Pattern length
    @return: Number of hosts with that pattern length
    """
    if not length > 0:
        Error.printErrorAndExit("getNumberOfHostsWithPatternLength: length must be > 0, was " + str(length))
    try:
        return len(SIZES[length])
    except KeyError:
        return 0


def isValidTarget(host):
    """Check if the provided hostname is a valid target (meaning a pattern exists for it).

    @param host: The hostname
    @return: True or False
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
    return len(PATTERNS[host])


def getAllPossibleTargets():
    """Get a list of all targets that have a pattern associated with them

    @return: List of targets
    """
    return PATTERNS.keys()


def getAllTargetsWithLength(length):
    """Get a list of all targets whose patterns have a specific length

    @param length: The length
    @return: A list of possible Targets
    """
    if not length > 0:
        Error.printErrorAndExit("getAllTargetsWithLength: length must be > 0, was " + str(length))
    try:
        return SIZES[length]
    except KeyError:
        return []


def addTarget(target, pattern):
    """Add a new target to the dictionary of targets.

    @param target: hostname of the target (String)
    @param pattern: query pattern (set)
    """
    assert target != ""                 # Target not empty
    assert pattern != set([])           # Pattern not empty
    assert not isValidTarget(target)    # Target does not exist yet
    PATTERNS[target] = pattern
    try:
        SIZES[len(pattern)].append(target)
    except KeyError:
        SIZES[len(pattern)] = [target]
    QUERIES.update(pattern)
    return
