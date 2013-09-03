#!/usr/bin/python2.7
# encoding: utf-8
'''
DRQPatternAttack -- Implementing the Pattern Attack on DNS Range Queries

DRQPatternAttack is a simulator for the Pattern Attack on DNS Range Queries, as described in my Bachelor Thesis.

@author:     Max Maass

@copyright:  2013 Max Maass

@license:    To be determined

@contact:    max [aett] velcommuta.de (PGP Key ID: 3408825E, Fingerprint 84C4 8097 A3AF 7D55 189A  77AC 169F 9624 3408 825E)
@deffield    updated: Updated
'''

import sys
import os
from var import Config      # Config Variables
import parse.Pattern        # Parser for pattern file
import generate.DRQ         # DNS Range Query generator
import attacker.Pattern     # Attacker
import data.DB              # Database
import util.Progress        # Progress Bar
import util.Error           # Error logging
import util.Parallel        # Parallel Processing

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

__all__ = []
__version__ = '0.4.4'
__date__ = '2013-03-15'
__updated__ = '2013-08-26'


class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg

    def __str__(self):
        return self.msg

    def __unicode__(self):
        return self.msg

def getGeneratorFor(genID):
    """Generator selector

    Resolves a GeneratorID to the matching generator.

    @param genID: The ID of the Generator
    @return: A Reference to the type of Generator (that can be directly initialized, if needed)
    """
    generators = {1: generate.DRQ.BRQ().NDBRQ,
                  2: generate.DRQ.BRQ().DFBRQ,
                  3: generate.DRQ.BRQ().FDBRQ,
                  4: generate.DRQ.PBRQ().NDBRQ,
                  5: generate.DRQ.PBRQ().DFBRQ,
                  6: generate.DRQ.PBRQ().FDBRQ}
    return generators[genID]


def getAttackerFor(attID):
    """Attacker selector

    Resolves an AttackerID to the matching attacker.

    @param attID: The ID of the attacker
    @return: A Reference to the type of Attacker (that can be directly initialized, if needed)
    """
    attackers = {1: attacker.Pattern.NDBPattern,
                 2: attacker.Pattern.DFBPatternBRQ,
                 3: attacker.Pattern.FDBPattern,
                 4: attacker.Pattern.NDBPattern,
                 5: attacker.Pattern.DFBPatternPRQ,
                 6: attacker.Pattern.FDBPattern}
    return attackers[attID]


def chooseTargets(number_of_targets):
    """Choose a number of random targets

    This function will choose number_of_targets random patterns to be attacked.

    @param number_of_targets: The number of targets to be returned.
    @return: A list of targets
    """
    # TODO: Currently not unique. Change?
    returnValue = []
    for i in range(number_of_targets):
        returnValue.append(data.DB.getRandomTarget())
    return returnValue


def generateFor(generatorInstance, domain):
    """Generate a range Query

    Generates a range Query for the provided domain using the provided, uninitialized generatorInstance

    @param generatorInstance: An uninitialized Generator, as returned by getGeneratorFor(genID)
    @param domain: The domain the generator should generate a range query for.
    @return: The result of the generator.
    """
    return generatorInstance().generateDRQFor(domain)


def attack(attackInstance, inputValue):
    """Start an attack

    Attack a provided inputValue using the provided, uninitialized attackInstance.

    @param attackInstance: An uninitialized attacker, as returned by getAttackerFor(attID).
    @param inputValue: A valid input value for said attacker.
    @return: The results of the attack.
    """
    return attackInstance().attack(inputValue)


def attackList(attackerInstance, generatorInstance, list_of_domains):
    """Attack a list of targets

    Generate range queries for a list of domains and attack them using the provided attackerInstance.

    @param attackerInstance: An uninitialized Attacker, as returned by getAttackerFor(attID)
    @param generatorInstance: An uninitialized Generator, as returned by getGeneratorFor(genID)
    @param list_of_domains: A list of Domains, as returned by chooseTargets(number_of_targets)
    @return: A Dictionary, mapping domains to the results of the attackers.
    """
    stat = util.Progress.Bar(len(list_of_domains), "=")
    returnValue = {}
    for domain in list_of_domains:
        returnValue[domain] = attack(attackerInstance, generateFor(generatorInstance, domain))
        stat.tick()
    return returnValue


def attackParallel(attackerInstance, generatorInstance, list_of_domains):
    """Attack a list of targets using multiple threads

    Parallelize the generation and attacking of a list of domains using multiple threads.
    Delegates all work to the util.Parallel module.

    @param attackerInstance: An uninitialized Attacker, as returned by getAttackerFor(attID)
    @param generatorInstance: An uninitialized Generator, as returned by getGeneratorFor(genID)
    @param list_of_domains: A list of Domains, as returned by chooseTargets(number_of_targets)
    @return: The result of the util.Parallel.parallelize function (a dictionary, similar to attackList)
    """
    stat = util.Progress.Bar(len(list_of_domains), "=")
    return util.Parallel.parallelize(attackerInstance, generatorInstance, list_of_domains, stat)


def validateResults(attackResultDictionary):
    """Validate results

    Validated the results of a finished attack, checking if the correct Domain is included in the results.

    @param attackResultDictionary: A result dictionary, as returned by attackList or attackParallel
    @return True if the correct result was always found, terminates program otherwise.
    """
    print "Validating Results..."
    i = 0
    for domain in attackResultDictionary:
        if domain not in attackResultDictionary[domain]:
            sys.stderr.write("ERROR: " + domain + " not in results\n")
            sys.stderr.write("       Previously checked " + str(i) + " correct results.\n")
            sys.stderr.flush()
            return False
        else:
            if not Config.QUIET:
                print "Target:       " + domain
                print "# possible:   " + str(len(attackResultDictionary[domain]))
                print "len(pattern): " + str(data.DB.getPatternLengthForHost(domain))
                print "=============================="
            i += 1
    return True


def generateStats(attackResultDictionary):
    # TODO: Rework Docstring, currently horrible wording
    """Generate stats

    Generate a set of statistics for a provided attackResultDictionary

    @param attackResultDictionary: A result Dictionary, as returned by attackList or attackParallel
    @return: Two dictionaries, showing the number of patterns with a specific number of results
    """
    seperateSum = {}
    overallSum = {}
    for domain in attackResultDictionary:
        pattern_length = data.DB.getPatternLengthForHost(domain)
        ard_len = len(attackResultDictionary[domain])
        try:
            seperateSum[pattern_length]
        except KeyError:
            seperateSum[pattern_length] = {}
        try:
            seperateSum[pattern_length][ard_len] += 1
        except KeyError:
            seperateSum[pattern_length][ard_len] = 1
        try:
            overallSum[ard_len] += 1
        except KeyError:
            overallSum[ard_len] = 1
    # Currently, we only have regular stats. They will be converted to cumulative stats in the next step
    return seperateSum, overallSum


def printStats(seperateSum, overallSum):
    # TODO: Update Docstring
    """Print stats

    Print the results of generateStats in a matlab-friendly format.

    @param seperateSum: TODO
    @param overallSum: TODO
    """
    filename = "m-" + str(Config.MODENUM) + "-N-" + str(Config.RQSIZE) + "-S-" + "XXX" + "-M-" + "ALL" + ".txt" # TODO: Change this once the parameter to vary the sets is implemented
    with open(filename, "w") as fo:
        fo.write("# Statistics for m=%i, N=%i, S=%s, all M\n" % (Config.MODENUM, Config.RQSIZE, "XXX")) # TODO: Change this (incl. %s) once the parameter to vary the sets is implemented
        fo.write("# k-definiteness count\n")
        vSum = 0
        for i in range(1, max(overallSum)+1, 1):
            try:
                vSum += overallSum[i]
            except KeyError:
                pass
            fo.write("%i %i\n" % (i, vSum))
    for k in seperateSum:
        filename = "m-" + str(Config.MODENUM) + "-N-" + str(Config.RQSIZE) + "-S-" + "XXX" + "-M-" + str(k) + ".txt" # TODO: Change this once the parameter to vary the sets is implemented
        with open(filename, "w") as fo:
            fo.write("# Statistics for m=%i, N=%i, S=%s, M=%i\n" % (Config.MODENUM, Config.RQSIZE, "XXX", k)) # TODO: Change this (incl %s) once the parameter to vary the sets is implemented
            fo.write("# k-definiteness count\n")
            vSum = 0
            for i in range(1, max(seperateSum[k])+1, 1):
                try:
                    vSum += seperateSum[k][i]
                except KeyError:
                    pass
                fo.write("%i %i\n" % (i, vSum))

def main(argv=None):  # IGNORE:C0111
    """Main function

    Parses CLI options and calls the other functions in order.
    """
    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)
    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    # program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = ''''''  # % (program_shortdesc, str(__date__))
    program_epilogue = '''Modes of Operation:
  1) No distinguishable Blocks \t\t- Random Generation
  2) Distinguishable first Block \t- Random Generation
  3) Fully distinguishable Blocks \t- Random Generation
  4) No distinguishable Blocks \t\t- Pattern-based generation
  5) Distinguishable first Block \t- Pattern-based generation
  6) Fully distinguishable Blocks \t- Pattern-based generation

  Please consult the thesis to find more information about the modes'''

    try:
        # Setup argument parser
        # TODO: Sort these arguments in a way that makes sense (Order is preserved in final programs --help)
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter, epilog=program_epilogue)
        group1 = parser.add_mutually_exclusive_group()
        group1.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="enable verbose output (show more information).")
        group1.add_argument("-q", "--quiet", dest="quiet", action="store_true", help="enable quiet mode.")
        parser.add_argument("-m", '--mode', dest="mode", help="Enable a specific mode of operation. See below for possible options. [default %(default)s]", default="1", choices=[1, 2, 3, 4, 5, 6], type=int)
        parser.add_argument('--version', action='version', version=program_version_message)
        parser.add_argument('-s', '--size', dest="num", help="Size of the range query [default %(default)s]", default="50", type=int)
        parser.add_argument('-c', '--count', dest="cnt", help="Number of random targets to be tried [default %(default)s]", default="50", type=int)
        parser.add_argument('-t', '--threads', dest="threads", help="Number of Threads used for processing [default %(default)s]", default="1", type=int)
        parser.add_argument('--stat', dest="stat", help="Show statistics about the accuracy of the algorithm", action="store_true")
        group2 = parser.add_mutually_exclusive_group()
        group2.add_argument('--target', dest="target", metavar="url", help="Attack this domain", type=str, default="")
        group2.add_argument('--all', dest="attack_all", action="store_true", help="Attack all possible targets (may take a long time). Implies -q, --stat")
        parser.add_argument("file", help="select pattern file.")
        # TODO: Add Argument for Benchmark mode? Time execution of attack and give stats for that as well?
        # TODO: Add Parameters to determine dataset sizes (for variation in stat collection)
        # Also change thesis once this is implemented.

        # Process arguments
        args = parser.parse_args()
        Config.VERBOSE = args.verbose
        Config.QUIET = args.quiet
        Config.INFILE = args.file
        Config.RQSIZE = args.num
        Config.STAT = args.stat
        Config.THREADS = args.threads
        Config.MODENUM = args.mode
        if args.attack_all:
            Config.STAT = True
            Config.VERBOSE = False
            Config.QUIET = True

        # Parse input file
        parse.Pattern.parse()

        # Choose targets
        target_list = []
        if args.target != "":
            target_list.append(args.target)
        elif args.attack_all:
            target_list = data.DB.getAllPossibleTargets()
        else:
            target_list = chooseTargets(args.cnt)

        # Get Generators and Attackers
        generatorInstance = getGeneratorFor(args.mode)
        attackerInstance = getAttackerFor(args.mode)

        if not Config.QUIET:
            print "Beginning Attack..."

        # Begin Attack procedure
        if Config.THREADS > 1:
            attackResult = attackParallel(attackerInstance, generatorInstance, target_list)
        else:
            attackResult = attackList(attackerInstance, generatorInstance, target_list)
        if not Config.STAT:
            if not validateResults(attackResult):
                util.Error.printErrorAndExit("Something went wrong. Exiting!")
        if Config.STAT or Config.VERBOSE:
            seperateSum, overallSum = generateStats(attackResult)
            printStats(seperateSum, overallSum)
        return 0

    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return 1
    except Exception, e:
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        return 2

if __name__ == "__main__":
    sys.exit(main())
