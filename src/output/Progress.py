'''
Progress Bar

This Module will be used to display a progress bar, if enabled.

Code inspired by http://stackoverflow.com/a/3160819/1232833, but modified.

@author: Max Maass
'''
import sys
from math import floor
import os

def getTTYSize():
    columns = 50
    if os.name == "posix":
        try:    # try to get terminal size using "stty size" (on Linux)
            _, columns = os.popen('stty size', 'r').read().split()
        except: # If anything goes wrong, stop trying and use standard value
            pass
    return int(columns)

class Bar():
    # TODO: Think about interaction with -q
    def __init__(self,eventCount,pip):
        ttywidth = getTTYSize()
        self.onePip = float((ttywidth-2) / float(eventCount))
        #self.stepValue = float(eventCount / (ttywidth-2))
        self.state = 0.0
        self.pip = pip
        self.eventCount = eventCount
        # setup progress bar
        sys.stderr.write("[%s]" % (" " * (ttywidth-2)))
        sys.stderr.flush()
        sys.stderr.write("\b" * (ttywidth-1)) # return to start of line, after '['
    
    def tick(self):
        cstate = self.state
        nstate = cstate +1
        if floor(cstate * self.onePip) < floor(nstate * self.onePip):
            sys.stderr.write("%s" % (self.pip * int(floor(nstate * self.onePip) - floor(cstate * self.onePip))))
            sys.stderr.flush()
        if nstate == self.eventCount:
            print ""
        self.state = nstate
        return