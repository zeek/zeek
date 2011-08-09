# See the file "COPYING" in the main distribution directory for copyright.
"""
This module contains pseudo-random collections of functions and methods that are used elsewhere in the project.
"""

import os
import re

class BroLogUtil(object):
    """
    Container class for a few useful file / extension related functions.

    Also maintains a registry for file extension / type specification pairs.  These pairs
    are used to automatically determine how to decode certain files.
    """
    EXT_EXPR = re.compile(r"[^/].*?\.(.*)$")
    logtypes = dict()

    @staticmethod
    def supports(path):
        """
        Pull out the file extension and see if we have a LogSpec that knows how to
        handle this file type.
        """
        base, fname = os.path.split(path)
        return BroLogUtil.get_ext(fname) in BroLogUtil.logtypes

    @staticmethod
    def get_field_info(path):
        """
        Returns a reference to the LogSpec (as determined by file extension) best suited
        to handle this file type.
        """
        base, fname = os.path.split(path)
        return BroLogUtil.logtypes[ BroLogUtil.get_ext(fname) ]

    @staticmethod
    def register_type(file_ext, target):
        """
        Associates a certain file extension with a certain BroLogSpec
        """
        BroLogUtil.logtypes[file_ext] = target

    @staticmethod
    def get_ext(path):
        """
        Determines the file extension for a given file.  The regex it uses for
        this purpose is very aggressive; everything beyond the first '.' is considered
        to be part of the file extension.

        TODO: Is this really the best way to do this?
        """
        match = BroLogUtil.EXT_EXPR.search(path)
        if(match):
            return match.group(1)
        return None

