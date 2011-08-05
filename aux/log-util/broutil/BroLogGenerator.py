import itertools
import random

from BroLogOptions import *

class BroLogGenerator(object):
    def __init__(self, log_list):
        self._logs = log_list
        self._filter = None
        self._must_compute = True
        self._accumulator = None

    def filter(self, f):
        self._filter = f

    def get_stats(self, field):
        if(self._must_compute):
            self.compute_stats()
        if(self._must_compute):
            return None  # Computation failed for some reason
        return self._accumulator[field]

    def get_fields(self):
        if(self._logs and len(self._logs) >= 1):
            return self._logs[0].names

    def gettypes(self):
        if(self._logs and len(self._logs) >= 1):
            return self._logs[0].types

    def compute_stats(self):
        if not self._logs:
            return False
        accumulator = None
        for log in self._logs:
            if(BroLogOptions.verbose):
                print "Processing " + log.path()
            log_type = log.type()
            log_fields = log_type.names
            log_fd = log_type.open(log.path())
            sampling = float(log._sampling)
            if accumulator:
                log_type._accumulator = accumulator
            def accum(line):
                line = zip(log_fields, line)
                map(lambda x: log_type._accumulator[ x[0] ].accumulate(x[1]), line)
            if(sampling < .999):
                map(accum, (l for l in log_fd if random.random() < sampling))
            else:
                map(accum, log_fd)
            accumulator = log_type._accumulator
        self._accumulator = accumulator
        for acc in self._accumulator.keys():
            self._accumulator[acc].postprocess()
        self._must_compute = False

    def entries(self):
        if not self._logs:
            return False
        
        rlist = []
        for log in self._logs:
            if(BroLogOptions.verbose):
                print "Processing " + log.path()
            log_type = log.type()
            log_fields = log_type.names
            log_fd = log_type.open(log.path())
            translator = log_type._translator
            # Very ugly, but also pretty fast.
            class BroLogEntry(object):
                def __init__(self, vals):
                    self._vals = vals

                def __getattr__(self, name):
                    self.__dict__[name] = translator[name](self._vals[name]) 
                    return self.__dict__[name]
            
                def __getitem__(self, name):
                    return translator[name](self._vals[name])

                def type(self):
                    return log_type

                def types(self):
                    return log_type.types

            def field_transform(x):
                return BroLogEntry(dict(zip(log_fields, x)))

            if not log_fd:
                continue
            rlist.append(itertools.imap(field_transform, log_fd))
        return itertools.chain.from_iterable(rlist)

