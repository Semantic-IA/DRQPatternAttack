#!/usr/bin/python2.7
# encoding: utf-8
'''
DRQPatternAttack -- Implementing the Pattern Attack on DNS Range Queries

DRQPatternAttack is a simulator for the Pattern Attack on DNS Range Queries, as described in my Bachelor Thesis.

@author:     Max Maass
        
@copyright:  2013 Max Maass
        
@license:    To be determined

@contact:    0maass@informatik.uni-hamburg.de (PGP Key ID: 6F3891FC, Fingerprint 146D 278F F603 D22F 8906  373C 3C58 CF40 6F38 91FC)
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
        parser.add_argument("file", help="select pattern file.")
        # TODO: Add Arguments to determine the used combination of generator and attacker
        # TODO: Add Argument for interactive mode and document it in the help
        
        # Process arguments
        args = parser.parse_args()
        Config.VERBOSE = args.verbose
        Config.QUIET = args.quiet
        Config.INFILE = args.file
        Config.RQSIZE = args.num
        Config.STAT = args.stat
        
        # Starting here: Debug and testing code. For the final version, this should be cleaned up and
        # refactored into modules and functions.
        # TODO: Implement usage of planned parameters determining combination of generator and attacker
        # TODO: Add a dictionary mapping parameters to generators and attackers
        # TODO: Add a compatibility Database for these parameters
        # TODO: Refactor this to be modular with good documentation and less horrible code
        # TODO: Add interactive mode as per the parameter proposed above
        stat = {}
        parse.Pattern.parse()
        for i in range(args.cnt):
            t = data.DB.chooseRandomTarget()
            block = generate.DRQ.FDBRQ().generateDRQFor(t)
            at = attacker.Pattern.FDBPattern()
            res = at.attack(block)
            lr = len(res)
            lp = len(data.DB.PATTERNS[t])
            if not Config.QUIET:
                print "Target: " + t
                #print "Possible targets: " + str(res)
                print "# possible targets: " + str(lr)
                if t not in res:
                    print "[!!!] Target not in result!"
                    return 2
                if Config.VERBOSE:
                    print "[V] Length of target pattern: " + str(lp)
            if Config.VERBOSE or Config.STAT:
                if lp in stat:
                    if lr in stat[lp]:
                        stat[lp][lr] += 1
                    else:
                        stat[lp][lr] = 1
                else:
                    stat[lp] = {}
                    stat[lp][lr] = 1
            if not Config.QUIET:
                print "================================="
        if Config.VERBOSE or Config.STAT:
            for okey in stat:
                for ikey in stat[okey]:
                    print str(okey) + ":" + str(ikey) + ":" + str(stat[okey][ikey])
        
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
