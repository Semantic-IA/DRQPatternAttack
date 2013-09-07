'''
Holds configuration variables

@author: Max Maass
'''
QUIET = False       # Quiet mode enabled?
VERBOSE = False     # Verbose mode enabled?
STAT = False        # Stat only mode
INFILE = ""         # Path to pattern file
RQSIZE = 0          # Range Query Size (Number of Queries per Range Query block)
THREADS = 1         # Number of Threads (or, more accurately, subprocesses) to be used
MODENUM = -1		# Number of the active mode
DBSPLIT = 0			# Size of reduced Database
# TODO: Yikes. Rework DBSPLIT to something sensible