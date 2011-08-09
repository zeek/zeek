"""
Making pylint complain less.  Must. . . hit. . . 7.0. . .
"""

class BroLogOptions(object):
    """
    Helper class to store global log options.  Not much here so far :)
    verbose -- Log library will dump stuff to stdout via 'print' as it works.
    interactive -- Will allow the user to address issues that come up rather than returning from a function with an error.
    """
    verbose = False
    interactive = False

