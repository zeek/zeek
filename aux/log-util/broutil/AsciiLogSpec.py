import bz2
import csv
import gzip
import itertools
import re

from BroLogSpec import *
from BroLogUtil import *

class AsciiLogSpec(BroLogSpec):
    RE_TYPESPEC = re.compile(r"\s*#(.*?)\n?")  # Pull out everything after a comment character
    RE_PATHSPEC = re.compile(r"\s*#\s*path:'(.*)'")  # Pull out the logfile path name (as defined by bro; this is *NOT* the filesystem path)
    RE_SEPARATOR = re.compile(r"\s*#\s*separator:'(.*)'")  # Pull out the separator character
    RE_TYPE_ENTRY = re.compile(r"(.*)=(.*)")  # Extract FIELD=BRO_TYPE

    def __init__(self):
        self._fields = []
        self.names = []
        self.types = []
        self._bro_log_path = ""
        self._separator = ""
        self._valid = False
        self._translator = dict()
        self._accumulator = dict()

    def raw_open(self, path):
        if(BroLogUtil.get_ext(path) == 'log.gz'):
            ascii_file = gzip.GzipFile(path)
        elif(BroLogUtil.get_ext(path) == 'log.bz2'):
            ascii_file = bz2.BZ2File(path)
        else:
            ascii_file = open(path)
        return ascii_file
    
    def _open_filter(self, line):
        return line[0][0] != '#'

    def open(self, path):
        if(BroLogUtil.get_ext(path) == 'log.gz'):
            ascii_file = gzip.GzipFile(path)
        elif(BroLogUtil.get_ext(path) == 'log.bz2'):
            ascii_file = bz2.BZ2File(path)
        else:
            ascii_file = open(path, 'rb')
        self._null_check = re.compile('-' + self._separator)
        open_filter = self._open_filter
        return itertools.ifilter(open_filter, csv.reader(ascii_file, delimiter=self._separator))
        # return self.open_gen(csv.reader(ascii_file, delimiter=self._separator))

    def close(self, fd):
        fd.close()

    def load(self, path):
        ascii_file = self.raw_open(path)
        if(ascii_file):
            key = ascii_file.readline()
            m = AsciiLogSpec.RE_PATHSPEC.match(ascii_file.readline())
            if not m:
                # print "no bro path assignment (e.g. the 'conn' bit of something like 'conn.log' or 'conn.ds') found.  Skipping file..."
                return False
            self._bro_log_path = m.group(1)
            m = AsciiLogSpec.RE_SEPARATOR.match(ascii_file.readline())
            if not m:
                # print "no separator found.  Skipping file..."
                return False
            self._separator = m.group(1)
            fields = ascii_file.readline()
            if not self.parse(fields):
                # print "Unsupported logfile: " + path
                return False
            return True
        self.close(ascii_file)

    def parse(self, type_info):
        m = AsciiLogSpec.RE_TYPESPEC.match(type_info)
        if not m:
            return False
        type_array = re.sub("\s*#\s*", '', type_info).split(" ")
        m = [AsciiLogSpec.RE_TYPE_ENTRY.match(entry) for entry in type_array]
        self._fields = [ ( entry.group(1), entry.group(2) ) for entry in m]
        self.names = [ entry.group(1) for entry in m ]
        self.types = [ entry.group(2) for entry in m ]
        for entry in m:
            self._translator[ entry.group(1) ] = self._get_translator( entry.group(2) )
            self._accumulator[ entry.group(1) ] = self._get_accumulator( entry.group(2) )()

        if(len(self._fields) == 0):
            return False
        #for e in self._fields:
        #    print e
        return True

    def types(self):
        return self._fields

