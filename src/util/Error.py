'''
Module to display error messages.

Created on May 18, 2013

@author: Max Maass
'''

from sys import stderr

def printErrorAndExit(error_message):
    """Docstring"""
    stderr.write("ERROR: " + error_message + "\n")
    exit(1)