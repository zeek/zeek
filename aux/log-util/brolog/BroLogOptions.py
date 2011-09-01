# See the file "COPYING" in the main distribution directory for copyright.
"""
All options related to the Bro log library are held within the BroLogOptions 
class defined in this module.
"""

class BroLogOptions(object):
    """
    Helper class to store global log options.  Not much here so far :)
    verbose -- Log library will dump stuff to stdout via 'print' as it works.
    interactive -- Will allow the user to address issues that come up rather 
                   than returning from a function with an error.
    int_null_val -- Used by default when a NULL character (often '-') is 
                    encountered in a field of type 'count', 'counter', or 'int'
    float_null_val -- Used by default when a NULL character (often '-') is 
                      encountered in a field of type 'time', 'interval', or
                      'float'
    """
    verbose = False
    interactive = False
    int_null_val = None
    float_null_val = None
