# See the file "COPYING" in the main distribution directory for copyright.
"""
Contains the bro log specification class.  This class defines how to parse and / or process a log file into
a list of string elements that can be processed / filtered elsewhere.
"""

import hashlib

from BroAccumulators import BroAccumulators
from BroLogOptions import BroLogOptions

class BroLogSpec(object):
    """
    Bro Log Specification.  This class is the base object for different types of log backends supported by Bro.
    LogSpec objects are responsible for opening, maintaining, and determining the types of various files (as
    identified by file extensions registered in __init__.py).

    Since some forms of SQL databases require a connection string rather than a file path, a TODO item
    is to add prefix support to paths (e.g. mysql:file_with_connection_string).  The details of retrieving
    file types and other data from each column and converting that into appropriate bro types is something
    of a design challenge, however, so this is something that probably needs some amount of thought before
    it is implemented.
    """
    def __init__(self):
        """
        self._fields -- A list of (name, bro_type) tuples describing the types of fields described here.
        self.names -- A list corresponding to the 'name' piece of self._fields.  Unzipping _fields led to
                      inefficient access, so this array was added in an attempt to optimize that.
        self.types -- A list corresponding to the 'type' piece of self._fields.  Unzipping _fields led to
                      inefficient access, so this array was added in an attempt to optimize that.
        self._bro_log_path -- The 'path' as understood and recorded by bro, e.g. "conn" or "ftp"
        self._valid -- Is this a valid specification.  TODO: remove this.
        self.translator -- Handles translation of variables from the log's format to a common format.  For
                            example, this might convert an integer timestamp to an equivalent floating point
                            value.  One entry in _translator is required per bro type.
        self.accumulator -- Handles accumulation of statistics as computed by BroLogGenerator.  This is a
                             dictionary of field_name:accumulator_function pairs.  For more info, see the
                             BroAccumulators module and / or compute_stats in BroLogGenerator.
        """
        self._fields = []
        self.names = []
        self.types = []
        self._bro_log_path = ""
        self._valid = False
        self.translator = dict()
        self.accumulator = dict()
        self.formatter = dict()

    def _get_accumulator(self, field_type):
        """
        Autogenerates a set of accumulators based on field type.  Double, integer, count, and counter types
        are assumed to warrant calculated statistics (e.g. mean, min, max, variance).  String, IP address,
        subnet, and port are grouped (number of each individual instance is recorded).  Time and interval is
        not supported at this time.
        """
        # Basic numeric accumulator: mean, variance, min, max
        if(field_type == 'double' or field_type == 'int' or field_type == 'count' or field_type == 'counter'):
            return BroAccumulators.StatsAccumulator

        # These types should be classified by group.
        if(field_type == 'port' or field_type == 'addr' or field_type == 'net' or field_type == 'subnet' or field_type == 'string'):
            return BroAccumulators.GroupAccumulator
        # Other types aren't supported as of yet.
        return BroAccumulators.DummyAccumulator

    def _get_formatter(self, field_type):
        """
        Autogenerates a set of formatters based on field type.  Default is 6-digit precision for floats, 
        print all digits for int / long, and print a string value otherwise.  These can be customized
        by modifying relevant fields in BroLogOptions
        """
        if(field_type == 'double' or field_type == 'time' or field_type == 'interval'):
            return "%.6f"
        if(field_type == 'int' or field_type == 'count' or field_type == 'counter'):
            return "%d"
        return "%s"

    def _get_translator(self, field_type):
        """
        Autogenerates a set of translators based on field_type.  Double, time, and interval values are
        treated as floating-point numbers.  Integer, count, and counter are treated as integers.  All
        other types are treated as strings.
        """
        if(field_type == 'double' or field_type == 'time' or field_type == 'interval'):
            null_val = BroLogOptions.float_null_val
            def get_val(val):
                try:
                    return float(val)
                except:
                    return null_val
        elif(field_type == 'int' or field_type == 'count' or field_type == 'counter'):
            null_val = BroLogOptions.long_null_val
            def get_val(val):
                try:
                    return long(val)
                except:
                    return null_val 
        else:
            def get_val(val):
                return val
        return get_val

    def fields(self):
        """
        Quick wrapper to return self._fields.
        TODO: modify this to zip(self.names, self.types)
        """
        return self._fields

    def supported(self):
        """
        'supported' should return True if this log type is supported on this platform, and false otherwise.
        See example in DsLogSpec for details.
        """
        return True

    def get_bro_path(self):
        """
        Returns the internal bro path used when creating this log file (as parsed from the log file).  Log
        files that share a common bro path (e.g. 'conn', 'ftp') are grouped into a single logical set of
        log files.
        """
        return self._bro_log_path

    def id(self):
        """
        Returns an md5 sum of the log path and the field name,type pairs.  Two type specifications are
        considered equal if their ids are equal.  This is used for sanity checking when scanning large
        directories of log files (e.g. to detect when old-form and new-form log files are mixed in a
        single directory.
        """
        m = hashlib.md5()
        m.update(str(self._bro_log_path))
        m.update(str(self._fields))
        return m.hexdigest()

    def valid(self):
        """
        Returns true if this spec refers to a valid path, or false otherwise.  Used only as a way
        for the BroLogFile to retrieve the value of the load; this should probably be refactored
        away.
        """
        return self._valid

    def __str__(self):
        """
        String format is: <MD5_HASH> : <BRO_PATH> -- <FIELD TUPLE>
        """
        return (self.id() + " : " + self._bro_log_path + " -- " + str(self._fields))

    def __repr__(self):
        """
        String format is: <MD5_HASH> : <BRO_PATH> -- <FIELD TUPLE>
        """
        return (self.id() + " : " + self._bro_log_path + " -- " + str(self._fields))

    def __eq__(self, other):
        """
        If both classes descend from BroLogSpec and their md5sums are equal, they're considered to
        effectively be the same type.
        """
        if issubclass(other.__class__, BroLogSpec):
            return self.id() == other.id()
        return False

    def __ne__(self, other):
        """
        True if hashes are not equivalent, and false otherwise.
        """
        return not self.__eq__(other)

    def __hash__(self):
        """
        Returns an internal python hash of the md5 string.  MD5 string is used so that modifications to id() will
        be reflected in __hash__ and __eq__ (DRY ftw).
        """
        return hash(self.id())

