"""
This is a quick handler for old connection log formats.  This can be used to manipulate old log files
in combination with new log files, with the caveat that the type differences can have an odd effect
on the results.
"""
# ts, duration, id.orig_h, id.resp_h, service, id.orig_p, id.resp_p, ?, ?, conn_state, ?

# This format is a manual specification that matches old (1.x) bro conn log file types.

import bz2
import csv
import gzip
import itertools
import re

from BroLogSpec import BroLogSpec
from BroLogUtil import BroLogUtil

class OldConnLogSpec(BroLogSpec):
    """
    Specification for old-style conn.log files.
    """
    @staticmethod
    def close(file_obj):
        """
        Closes a log file.
        """
        file_obj.close()

    def __init__(self):
        """
        Static initialization of lots of stuff here; since we're only dealing with a *single type* of file, all the
        types are known.  There's no reason to load and / or parse the file, save to do a quick sanity check to
        make sure it appears to match this format.
        """
        super(OldConnLogSpec, self).__init__()
        self._fields = [('ts', 'time'), ('duration', 'interval'), ('id.orig_h', 'addr'), ('id.resp_h', 'addr'), \
                        ('service', 'string'), ('id.orig_p', 'port'), ('id.resp_p', 'port'), ('proto', 'string'), \
                        ('orig_bytes', 'count'), ('resp_bytes', 'count'), ('conn_state', 'string'), ('???', 'string')]
        
        self.types = [ field[1] for field in self._fields ]
        self.names = [ field[0] for field in self._fields ]
        self._bro_log_path = "conn"
        self._separator = " "

        for pair in self._fields:
            self.translator[pair[0]] = self._get_translator(pair[1])
            self.accumulator[pair[0]] = self._get_accumulator(pair[1])()

    def raw_open(self, path):
        """
        Used for the load method, since we need a raw line rather than a csv-processed thing.
        """
        ascii_file = open(path)
        return ascii_file
    
    def open(self, path):
        """
        Opens an old-style log format and provides rows as lists of strings via the python csv module.
        """
        ascii_file = open(path, 'rb')
        self._null_check = re.compile(r'\?' + self._separator)
        return csv.reader(ascii_file, delimiter=self._separator)

    def load(self, path):
        """
        Opens the file and does a quick sanity check to make sure it looks like a valid old-style log.
        """
        ascii_file = self.raw_open(path)
        if(ascii_file):
            key = ascii_file.readline()
            if(len(key.split(' ')) < 11 or len(key.split(' ')) > 12):  # Count the number of fields in the file.  Should be 11 or 12.
                return False
            self.close(ascii_file)
            return True
        return False

    def parse(self, type_info):
        """
        TODO: Remove this.
        """
        return True

    def fields(self):
        """
        Returns a list of field_name,type tuples; see __init__ to see how this is defined.
        """
        return self._fields

