import os

from BroLogUtil import *
from BroLogFile import *
from BroLogGenerator import *

class BroLogManager(object):
    def __init__(self, sampling=1.0):
        self._path = None
        self._logfiles = []
        self._logobj = []
        self._total_count = 0
        self._success_count = 0
        self._sampling = sampling

    def load(self, paths):
        map(self.open, paths)

    def open(self, path):
        self._path = path
        if(os.path.isdir(path)):
            os.path.walk(path, lambda arg, dirname, fnames: arg.extend( [ os.path.join(os.path.abspath(dirname), f) for f in fnames ] ), self._logfiles)
        else:
            self._logfiles.append(path)
        self._logfiles = list(set(self._logfiles))  # Remove duplicates
        self._logfiles = [f for f in self._logfiles if BroLogUtil.supports(f) ]  # Only keep supported file types
        self._total_count = len(self._logfiles)
        self._logobj = [ BroLogFile(f, sampling=self._sampling) for f in self._logfiles ]
        self._logobj = [ f for f in self._logobj if f.valid() ]
        self._success_count = len(self._logobj)
        self._logs = dict()
        for obj in self._logobj:
            if obj.bro_path() not in self._logs:
                self._logs[obj.bro_path()] = []
            self._logs[obj.bro_path()].append(obj)
        self._type_count = len(self._logs)
        self._log_gen = dict()
        for key in self._logs.keys():
            self._log_gen[key] = BroLogGenerator(self._logs[key])
        # Quick sanity check; make sure types are consistent across bro log paths.  Note that if
        # this is not true, Bad Things (tm) could happen.
        for key in self._logs.keys():
            tmp_id = None
            for obj in self._logs[key]:
                if not tmp_id:
                    tmp_id = obj.type_id()
                else:
                    if(tmp_id != obj.type_id()):
                        print "[WARNING] Multiple types found for path: " + obj.bro_path()
                        # print tmp_id
        del self._logobj

    def get(self, key):
        if key in self._log_gen:
            return self._log_gen[key]
        return None

    def __getitem__(self, key):
        if key in self._log_gen:
            return self._log_gen[key]
        return None

    def print_stats(self):
        print "Found " + str(self._total_count) + " logfiles."
        print "Successfully loaded " + str(self._success_count) + " logfiles."
        print "Identified " + str(self._type_count) + " unique bro paths."

