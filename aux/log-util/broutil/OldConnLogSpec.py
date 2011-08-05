# ts, duration, id.orig_h, id.resp_h, service, id.orig_p, id.resp_p, ?, ?, conn_state, ?

# This format is a manual specification that matches old (1.x) bro conn log file types.

import bz2
import csv
import gzip
import itertools
import re

from BroLogSpec import *
from BroLogUtil import *

class OldConnLogSpec(BroLogSpec):
    RE_TYPESPEC = re.compile(r"\s*#(.*?)\n?")  # Pull out everything after a comment character
    RE_PATHSPEC = re.compile(r"\s*#\s*path:'(.*)'")  # Pull out the logfile path name (as defined by bro; this is *NOT* the filesystem path)
    RE_SEPARATOR = re.compile(r"\s*#\s*separator:'(.*)'")  # Pull out the separator character
    RE_TYPE_ENTRY = re.compile(r"(.*)=(.*)")  # Extract FIELD=BRO_TYPE

    def __init__(self):
        self._fields = [('ts', 'time'), ('duration', 'interval'), ('id.orig_h', 'addr'), ('id.resp_h', 'addr'),\
                        ('service', 'string'), ('id.orig_p', 'port'), ('id.resp_p', 'port'), ('proto', 'string'),\
                        ('orig_bytes', 'count'), ('resp_bytes', 'count'), ('conn_state', 'string'), ('???', 'string')]
        
        self.types = [ field[1] for field in self._fields ]
        self.names = [ field[0] for field in self._fields ]
        self._bro_log_path = "conn"
        self._separator = " "
        self._translator = dict()
        self._accumulator = dict()

        for pair in self._fields:
            self._translator[pair[0]] = self._get_translator(pair[1])
            self._accumulator[pair[0]] = self._get_accumulator(pair[1])()

    def raw_open(self, path):
        ascii_file = open(path)
        return ascii_file
    
    def open(self, path):
        ascii_file = open(path, 'rb')
        self._null_check = re.compile(r'\?' + self._separator)
        return csv.reader(ascii_file, delimiter=self._separator)

    def close(self, fd):
        fd.close()

    def load(self, path):
        ascii_file = self.raw_open(path)
        if(ascii_file):
            key = ascii_file.readline()
            if(len(key.split(' ')) < 11 or len(key.split(' ')) > 12):  # Count the number of fields in the file.  Should be 11 or 12.
                return False
            self.close(ascii_file)
            return True
        return False

    def parse(self, type_info):
        return True

    def types(self):
        return self._fields

