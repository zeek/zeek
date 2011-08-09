# See the file "COPYING" in the main distribution directory for copyright.
"""
Describes a specification for the ASCII log format.  See BroLogSpec for details.
"""
import bz2
import csv
import gzip
import itertools
import re

from BroLogSpec import BroLogSpec
from BroLogUtil import BroLogUtil

class AsciiLogSpec(BroLogSpec):
    """
    This log specification handles ASCII logfiles.  GZIP, BZIP2, and plaintext are supported.
    """
    RE_TYPESPEC = re.compile(r"\s*#(.*?)\n?")  # Pull out everything after a comment character
    RE_PATHSPEC = re.compile(r"\s*#\s*path:'(.*)'")  # Pull out the logfile path name (as defined by bro; this is *NOT* the filesystem path)
    RE_SEPARATOR = re.compile(r"\s*#\s*separator:'(.*)'")  # Pull out the separator character
    RE_TYPE_ENTRY = re.compile(r"(.*)=(.*)")  # Extract FIELD=BRO_TYPE
    
    @staticmethod
    def close(file_obj):
        """
        Closes a file opened by this log spec.
        """
        file_obj.close()

    @staticmethod
    def _open_filter(line):
        """
        Filters comments from the file.
        """
        return line[0][0] != '#'


    def __init__(self):
        """
        See BroLogSpec for more information about what this does.
        """
        super(AsciiLogSpec, self).__init__()
        self._separator = ""
        self._valid = False

    def raw_open(self, path):
        """
        Returns a raw file object for load / parse to use.
        """
        if(BroLogUtil.get_ext(path) == 'log.gz'):
            ascii_file = gzip.GzipFile(path)
        elif(BroLogUtil.get_ext(path) == 'log.bz2'):
            ascii_file = bz2.BZ2File(path)
        else:
            ascii_file = open(path)
        return ascii_file
    
    def open(self, path):
        """
        Opens a file; will return the file as a CSV reader, which will return lists of fields, each of
        which is represented by a 'string'.
        """
        if(BroLogUtil.get_ext(path) == 'log.gz'):
            ascii_file = gzip.GzipFile(path)
        elif(BroLogUtil.get_ext(path) == 'log.bz2'):
            ascii_file = bz2.BZ2File(path)
        else:
            ascii_file = open(path, 'rb')
        self._null_check = re.compile('-' + self._separator)
        open_filter = AsciiLogSpec._open_filter
        return itertools.ifilter(open_filter, csv.reader(ascii_file, delimiter=self._separator))
        # return self.open_gen(csv.reader(ascii_file, delimiter=self._separator))

    def load(self, path):
        """
        Attempts to read and parse bro path and type information from the log file located at 'path'.  If this is successful,
        the file is assumed to be a valid log file and is treated as such.
        """
        ascii_file = self.raw_open(path)
        if(ascii_file):
            ascii_file.readline()
            match = AsciiLogSpec.RE_PATHSPEC.match(ascii_file.readline())
            if not match:
                # print "no bro path assignment (e.g. the 'conn' bit of something like 'conn.log' or 'conn.ds') found.  Skipping file..."
                return False
            self._bro_log_path = match.group(1)
            match = AsciiLogSpec.RE_SEPARATOR.match(ascii_file.readline())
            if not match:
                # print "no separator found.  Skipping file..."
                return False
            self._separator = match.group(1)
            fields = ascii_file.readline()
            if not self.parse(fields):
                # print "Unsupported logfile: " + path
                return False
            return True
        self.close(ascii_file)

    def parse(self, type_info):
        """
        Tries to read the schema embedded into this particular log file and use it to figure out the bro types and bro path associated
        with this file.  If successful, this function return true and the file is considered valid.
        """
        match = AsciiLogSpec.RE_TYPESPEC.match(type_info)
        if not match:
            return False
        type_array = re.sub("\s*#\s*", '', type_info).split(" ")
        match = [AsciiLogSpec.RE_TYPE_ENTRY.match(entry) for entry in type_array]
        self._fields = [ ( entry.group(1), entry.group(2) ) for entry in match]
        self.names = [ entry.group(1) for entry in match ]
        self.types = [ entry.group(2) for entry in match ]
        for entry in match:
            self.translator[ entry.group(1) ] = self._get_translator( entry.group(2) )
            self.accumulator[ entry.group(1) ] = self._get_accumulator( entry.group(2) )()

        if(len(self._fields) == 0):
            return False
        #for e in self._fields:
        #    print e
        return True

    def fields(self):
        return self._fields

