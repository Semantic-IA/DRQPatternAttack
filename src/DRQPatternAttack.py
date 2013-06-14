#!/usr/bin/python2.7
# encoding: utf-8
'''
DRQPatternAttack -- Implementing the Pattern Attack on DNS Range Queries

DRQPatternAttack is a simulator for the Pattern Attack on DNS Range Queries, as described in my Bachelor Thesis.

@author:     Max Maass

@copyright:  2013 Max Maass

@license:    To be determined

@contact:    0maass@informatik.uni-hamburg.de (PGP Key ID: 3408825E, Fingerprint 84C4 8097 A3AF 7D55 189A  77AC 169F 9624 3408 825E)
@deffield    updated: Updated
'''
# TODO: Überall "Aufrufmuster" => "Anfragemuster"
# FIXME: Irgendwo in -m 1 ist noch massiv der Wurm drin (stats geben BS aus). Check!
import sys
import os
from var import Config  # Config Variables
import parse.Pattern    # Parser for pattern file
import generate.DRQ     # DNS Range Query generator
import attacker.Pattern # Attacker
import data.DB          # Database
import util.Progress    # Progress Bar
import util.Error       # Error logging
import util.Parallel

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

__all__ = []
__version__ = '0.3.1'
__date__ = '2013-03-15'
__updated__ = '2013-05-26'


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
    generators = {1: generate.DRQ.BRQ().NDBRQ, 
                  2: generate.DRQ.BRQ().DFBRQ, 
                  3: generate.DRQ.BRQ().FDBRQ, 
                  4: generate.DRQ.PBRQ().NDBRQ, 
                  5: generate.DRQ.PBRQ().DFBRQ, 
                  6: generate.DRQ.PBRQ().FDBRQ}
    return generators[genID]


def getAttackerFor(attID):
    attackers = {1: attacker.Pattern.NDBPattern, 
                 2: attacker.Pattern.DFBPattern, 
                 3: attacker.Pattern.FDBPattern, 
                 4: attacker.Pattern.NDBPattern, 
                 5: attacker.Pattern.DFBPattern, 
                 6: attacker.Pattern.FDBPattern}
    return attackers[attID]


def chooseTargets(number_of_targets):
    returnValue = []
    for i in range(number_of_targets):
        returnValue.append(data.DB.getRandomTarget())
    return returnValue


def attack(attackInstance, inputValue):
    return attackInstance().attack(inputValue)


def generateFor(generatorInstance, domain):
    return generatorInstance().generateDRQFor(domain)


def attackList(attackerInstance, generatorInstance, list_of_domains):
    stat = util.Progress.Bar(len(list_of_domains), "=")
    returnValue = {}
    for domain in list_of_domains:
        returnValue[domain] = attack(attackerInstance, generateFor(generatorInstance, domain))
        stat.tick()
    return returnValue


def attackParallel(attackerInstance, generatorInstance, list_of_domains):
    stat = util.Progress.Bar(len(list_of_domains), "=")
    return util.Parallel.parallelize(attackerInstance, generatorInstance, list_of_domains, stat)


def validateResults(attackResultDictionary):
    i = 0
    for domain in attackResultDictionary.keys():
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
    returnValue = {}
    for domain in attackResultDictionary.keys():
        pattern_length = data.DB.getPatternLengthForHost(domain)
        if pattern_length in returnValue:
            returnValue[pattern_length]["sum"] += len(attackResultDictionary[domain])
            returnValue[pattern_length]["num"] += 1
        else:
            returnValue[pattern_length] = {}
            returnValue[pattern_length]["sum"] = len(attackResultDictionary[domain])
            returnValue[pattern_length]["num"] = 1
    return returnValue


def printStats(statDictionary):
    output1 = "results = ["
    output2 = "samples = ["
    for i in range(1, max(statDictionary.keys())+1, 1):
        try:
            output1 += (str(statDictionary[i]["sum"] / float(statDictionary[i]["num"])) + " ")
            output2 += (str(statDictionary[i]["num"]) + " ")
        except KeyError:
            output1 += "0 "
            output2 += "0 "
    output1 += "];"
    output2 += "];"
    print output1
    print output2


def main(argv=None):  # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)
    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
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

        # Process arguments
        args = parser.parse_args()
        Config.VERBOSE = args.verbose
        Config.QUIET = args.quiet
        Config.INFILE = args.file
        Config.RQSIZE = args.num
        Config.STAT = args.stat
        Config.THREADS = args.threads
        if args.attack_all:
            Config.STAT = True
            Config.VERBOSE = False
            Config.QUIET = True
        parse.Pattern.parse()
        target_list = []
        if args.target != "":
            target_list.append(args.target)
        elif args.attack_all:
            target_list = data.DB.getAllPossibleTargets()
        else:
            target_list = chooseTargets(args.cnt)
        generatorInstance = getGeneratorFor(args.mode)
        attackerInstance = getAttackerFor(args.mode)
        print "Beginning Attack..."
        if Config.THREADS > 1:
            attackResult = attackParallel(attackerInstance, generatorInstance, target_list)
        else:
            attackResult = attackList(attackerInstance, generatorInstance, target_list)
        if not validateResults(attackResult):
            util.Error.printErrorAndExit("Something went wrong. Exiting!")
        if Config.STAT or Config.VERBOSE:
            statResult = generateStats(attackResult)
            printStats(statResult)
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
