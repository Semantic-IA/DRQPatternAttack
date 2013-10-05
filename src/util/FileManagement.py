'''
Management of files and folders

@author: Max Maass
'''
import os
import var.Config
import util.Error

def openStatFile(M):
	"""openStatFile

	Open a statistics file, creating it and the directory structure it resides in, if necessary, and adding the relevant header information
	
	@param M: The pattern length for which the stat file is meant, or 0 if it is for pattern-length agnostic statistics.
	@return: A file handler
	"""
	path = "_output/m" + str(var.Config.MODENUM) + "/N" + str(var.Config.RQSIZE) + "/S" + str(var.Config.DBSPLIT) + "/"
	# Create string containing the path to the folder that will contain the file
	if not os.path.exists(path): # If the folder does not exist, create it
		try:
			os.makedirs(path)
		except:
			util.Error.printErrorAndExit("FileManagement: openStatFile: Error while creating " + path + ". Exiting.")
	if M == 0: 
		filename = "M-" + "ALL" + ".txt" # General statistics
	else:
		filename = "M-" + str(M) + ".txt" # Statistics specific to a pattern length
	fo = open(path + filename, "w") # Open file for writing. Will overwrite existing files!
	# Now we write some header information into the file to give it some context.
	if M == 0:
		fo.write("# Statistics for m=%i, N=%i, S=%i, all M\n" % (var.Config.MODENUM, var.Config.RQSIZE, var.Config.DBSPLIT))
	else:
		fo.write("# Statistics for m=%i, N=%i, S=%i, M=%i\n" % (var.Config.MODENUM, var.Config.RQSIZE, var.Config.DBSPLIT, M))
	fo.write("# k-definiteness count\n")
	# Return the opened file object
	return fo