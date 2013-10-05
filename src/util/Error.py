'''
Module to display error messages.

@author: Max Maass
'''

from sys import stderr


def printErrorAndExit(error_message):
    """Print error and exit

    Prints an error message and terminates execution of the program

    @param error_message: The error message to be printed (string)
    """
    stderr.write("[ERROR] " + error_message + "\n") # Write error msg to STDERR
    exit(1)
