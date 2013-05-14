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

import sys
import os
from var import Config  # Config Variables
import parse.Pattern    # Parser for pattern file
import generate.DRQ     # DNS Range Query generator
import attacker.Pattern # Attacker
import data.DB          # Database # TODO: Remove (debug import)

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

__all__ = []
__version__ = '0.2.1'
__date__ = '2013-03-15'
__updated__ = '2013-04-04'

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
    return generate.DRQ.BRQ().NDBRQ()

def getAttackerFor(attID):
    return attacker.Pattern.NDBPattern()

def chooseTargets(number_of_targets):
    returnValue = []
    for i in range(number_of_targets):
        returnValue.append(data.DB.chooseRandomTarget())
    return returnValue

def attack(attackInstance,inputValue):
    return attackInstance.attack(inputValue)

def generateFor(generatorInstance,domain):
    return generatorInstance.generateDRQFor(domain)

def attackList(attackerInstance,generatorInstance,list_of_domains):
    returnValue = {}
    for domain in list_of_domains:
        returnValue[domain] = attack(attackerInstance,generateFor(generatorInstance,domain))
    return returnValue

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
                print "Target:     " + domain
                print "# possible: " + str(len(attackResultDictionary[domain]))
                print "=============================="
            i += 1
    return True
    
def generateStats(attackResultDictionary):
    returnValue = {}
    for domain in attackResultDictionary.keys():
        pattern_length = len(data.DB.PATTERNS[domain])
        if pattern_length in returnValue:
            returnValue[pattern_length]["sum"] += len(attackResultDictionary[domain])
            returnValue[pattern_length]["num"] += 1
        else:
            returnValue[pattern_length] = {}
            returnValue[pattern_length]["sum"] = len(attackResultDictionary[domain])
            returnValue[pattern_length]["num"] = 1
    return returnValue

def printStats(statDictionary):
    output1 = "results = [0 "
    output2 = "samples = [0 "
    for i in range(1,max(statDictionary.keys()),1):
        try:
            output1 += (str(float(statDictionary[i]["sum"] / statDictionary[i]["num"])) + " ")
            output2 += (str(statDictionary[i]["num"]) + " ")
        except KeyError:
            output1 += "0 "
            output2 += "0 "
    output1 += "];"
    output2 += "];"
    print output1
    print output2
    
def main(argv=None): # IGNORE:C0111
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
    program_license = '''''' # % (program_shortdesc, str(__date__))

    try:
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
        group = parser.add_mutually_exclusive_group()
        group.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="enable verbose output (show more information). Verbose Information will be marked with a [V] in the output")
        group.add_argument("-q", "--quiet", dest="quiet", action="store_true", help="enable quiet mode (only show most likely result)")
        parser.add_argument('--version', action='version', version=program_version_message)
        parser.add_argument('-s', '--size', dest="num", help="size of the range query [default %(default)s]", default="50", type=int)
        parser.add_argument('-c', '--count', dest="cnt", help="Number of random targets to be tried [default %(default)s]", default="50", type=int)
        parser.add_argument('--stat', dest="stat", help="Show stats", action="store_true")
        parser.add_argument('--target', dest="target", help="Attack this domain", type=str, default="")
        parser.add_argument("file", help="select pattern file.")
        # TODO: Add Arguments to determine the used combination of generator and attacker
        # TODO: Add Argument for interactive mode and document it in the help
        # TODO: Add Argument for Benchmark mode? Time execution of attack and give stats for that as well?
        
        # Process arguments
        args = parser.parse_args()
        Config.VERBOSE = args.verbose
        Config.QUIET = args.quiet
        Config.INFILE = args.file
        Config.RQSIZE = args.num
        Config.STAT = args.stat

        # TODO: Implement usage of planned parameters determining combination of generator and attacker
        # TODO: Add a dictionary mapping parameters to generators and attackers
        # TODO: Add a compatibility Database for these parameters
        # TODO: Add interactive mode as per the parameter proposed above
        parse.Pattern.parse()
        target_list = []
        if args.target == "":
            target_list = chooseTargets(args.cnt)
        else:
            target_list = list(args.target)
        generatorInstance = getGeneratorFor(0)
        attackerInstance = getAttackerFor(0)
        attackResult = attackList(attackerInstance,generatorInstance,target_list)
        if not validateResults(attackResult):
            return 1
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
