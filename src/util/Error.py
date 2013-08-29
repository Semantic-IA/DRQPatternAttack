'''
Module to display error messages.

Created on May 18, 2013

@author: Max Maass
'''

from sys import stderr


def printErrorAndExit(error_message):
    """Print error and exit

    Prints an error message and terminates execution of the program

    @param error_message: The error message to be printed (string)
    """
    stderr.write("ERROR: " + error_message + "\n")
    exit(1)
