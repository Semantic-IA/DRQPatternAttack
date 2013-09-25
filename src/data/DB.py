'''
Holds the Data parsed from the pattern file for use in other modules

@author: Max Maass
'''
import random
import util.Error

PATTERNS = {}       # Database of all patterns
QUERIES = set()     # Database of all Queries
SIZES = {}          # Database mapping lengths to a list of domain patterns with that length
LENGTH = {}         # Database mapping domains to the lengths of their patterns
PATTERNS_C = {}     # Database of all patterns the client may use
QUERIES_C = set()   # Database of all queries the client may use
SIZES_C = {}        # Database mapping lengths to a list of domain patterns with that length that are allowed for the client
# Formats of the dictionaries:
# PATTERNS[domain] = Pattern_as_list
# QUERIES = set(all_known_queries)
# SIZES[length] = list_of_domains_with_pattern_length
# LENGTH[domain] = length_of_domain_pattern

# The databases have been split into those the attacker may use (PATTERNS, QUERIES, SIZES, LENGTH) and those the Client may use
# (PATTERNS_C, QUERIES_C, SIZES_C, LENGTH). In general, all *_C databases are subsets of their counterparts without the trailing
# _C.
# The following functions have been built so that they use the correct database. All functions using *_C-databases are only used
# by the client. Some of the other functions are also used by the client, but in their case, it makes no difference that the
# attacker database was used.
# The attacker does not know the contents of the *_C-databases.


def createDatabasePartition(size):
    """Partition the database

    This function prepares the database for use by determining the contents of the *_C-databases depending on the input value.

    The goal is to choose a number of patterns whose lengths add up to the size given as a parameter. If the parameter is set to
    -1, the whole dataset is used (PATTERNS_C == PATTERNS and so on).
    The result of this function is deterministically determined, using the target size as the random number generator seed.
    The RNG will be reset to a new, pseudorandom seed before this function terminates.

    @param size: The number of Queries the client database should contain (or -1, if the database should be the full set).
    @return: The number of queries QUERIES_C actually contains in the end.
    """
    # Currently, this function is DETERMINISTIC and CHECKS FOR DUPLICATES.
    if size > len(QUERIES):
        util.Error.printErrorAndExit("createDatabasePartition: size must be less than or equal to the number of unique queries (%i)" \
            % (len(QUERIES)))
    if size == -1 or size==len(QUERIES):
        PATTERNS_C.update(PATTERNS)
        QUERIES_C.update(QUERIES)
        SIZES_C.update(SIZES)
    else:
        # util.Error.printErrorAndExit("createDatabasePartition: Unimplemented for size=" + str(size))
        random.seed(size)
        # Deterministic RNG using the size as seed, so we get the same output every time for the same size.
        # This is desireable because we want the same database to be compared using different blocks sizes.
        # The output can only be properly compared if the data base is equal in all runs, hence we use a deterministic RNG here,
        # it will be re-seeded afterwards to allow (pseudo-)randomness in the rest of the process.
        domains = PATTERNS.keys()
        random.shuffle(domains)     # Shuffle the list of domains (deterministically)
        csize = 0                   # Initialize the variable containing the current size of the database
        for domain in domains:
            if csize + LENGTH[domain] <= size:  # The pattern will fit into our requested number, add it to the clients database
                PATTERNS_C[domain] = PATTERNS[domain]
                QUERIES_C.update(PATTERNS_C[domain])
                try:
                    SIZES_C[LENGTH[domain]].add(domain)
                except KeyError:
                    SIZES_C[LENGTH[domain]] = set([domain])
                csize = len(QUERIES_C)
            else: # The pattern length of domain is larger than the number of missing patterns, skip this pattern.
                continue
        random.seed()
        # Re-seed the RNG with the current system time or a better source, if one is available (determined by the python interpreter)
    return len(QUERIES_C)


def getRandomTarget():
    """Choose random Host from the list of possible targets

    The List of possible targets is the set of keys of the PATTERNS Dictionary.

    @return: A Hostname for which a pattern is known, as a string
    """
    return random.choice(PATTERNS_C.keys())


def getRandomHosts(number):
    """Choose random Hostnames from the set of all known hostnames

    If not enough queries are available, all available queries are returned.

    @param number: Number of Hostnames to return
    @return: A list of unique hostnames (as strings)
    """
    if not number > 0:
        util.Error.printErrorAndExit("getRandomHosts: number must be > 0, was " + str(number))
    return random.sample(QUERIES_C, min(number, len(QUERIES_C)))


def getRandomHostsByPatternLengthB(size, number, blacklist=set([])):
    """Choose random Hostnames from the set of all Hostnames with a pattern with a specified length, excluding a Blacklist.

    If not enough hosts are available, the maximum possible number of hosts with the requested pattern
    length is returned.

    @param size: The size of the pattern each hostname should have
    @param number: The number of Hostnames that should be returned
    @param blacklist: A set of Domain Names that should not be considered when drawing the random hosts
    @return: A list of unique Hostnames (as strings)
    """
    return random.sample(SIZES_C[size] - blacklist, min(number, getNumberOfHostsWithPatternLengthB(size, blacklist)))


def getRandomHostsByPatternLength(size, number):
    """Choose random Hostnames from the set of all Hostnames with a pattern with a specified length.

    If not enough hosts are available, the maximum possible number of hosts with the requested pattern
    length is returned.

    @param size: The size of the pattern each hostname should have
    @param number: The number of Hostnames that should be returned
    @return: A list of unique Hostnames (as strings)
    """
    return random.sample(SIZES_C[size], min(number, getNumberOfHostsWithPatternLength(size)))


def getNumberOfHostsWithPatternLengthB(length, blacklist=set([])):
    """Get the number of hosts with a particular pattern length, excluding a Blacklist

    @param length: Pattern length
    @param blacklist: Set of Hostnames that should not be considered
    @return: Number of hosts with that pattern length
    """
    if not length > 0:
        util.Error.printErrorAndExit("getNumberOfHostsWithPatternLengthB: length must be > 0, was " + str(length))
    try:
        return len(SIZES_C[length] - blacklist)
    except KeyError:
        return 0


def getNumberOfHostsWithPatternLength(length):
    """Get the number of hosts with a particular pattern length

    @param length: Pattern length
    @return: Number of hosts with that pattern length
    """
    if not length > 0:
        util.Error.printErrorAndExit("getNumberOfHostsWithPatternLength: length must be > 0, was " + str(length))
    try:
        return len(SIZES_C[length])
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
        util.Error.printErrorAndExit("getPatternForHost: Invalid host " + str(host))
    return PATTERNS[host].copy()


def getPatternLengthForHost(host):
    """Get the length of the pattern for the provided hostname

    @param host: Hostname
    @return: Length of the Pattern
    """
    if not isValidTarget(host):
        util.Error.printErrorAndExit("getPatternLengthForHost: Invalid host " + str(host))
    return LENGTH[host]


def getAllPossibleTargets():
    """Get a list of all targets that have a pattern associated with them

    @return: List of targets
    """
    return PATTERNS_C.keys()


def getAllTargetsWithLength(length):
    """Get a list of all targets whose patterns have a specific length

    @param length: The length
    @return: A list of possible Targets
    """
    if not length > 0:
        util.Error.printErrorAndExit("getAllTargetsWithLength: length must be > 0, was " + str(length))
    try:
        return list(SIZES_C[length])
    except KeyError:
        return []


def addTarget(target, pattern):
    """Add a new target to the dictionary of targets.

    @param target: hostname of the target (String)
    @param pattern: query pattern (set)
    """
    if not target != "":        # Target not empty
        util.Error.printErrorAndExit("addTarget: target must not be empty")
    if not pattern != set([]):  # Pattern not empty
        util.Error.printErrorAndExit("addTarget: Pattern must not be empty")
    if isValidTarget(target):   # Target does not exist yet
        util.Error.printErrorAndExit("addTarget: target must not exist yet")
    PATTERNS[target] = pattern
    length = len(pattern)
    try:
        SIZES[length].add(target)
    except KeyError:
        SIZES[length] = set([target])
    LENGTH[target] = length
    QUERIES.update(pattern)
    return