import itertools
import random

from BroLogOptions import *
from BroAccumulators import *

class BroLogGenerator(object):
    def __init__(self, log_list):
        self._logs = log_list
        self._filter = None
        self._must_compute = True
        self._accumulator = None

    def set_filter(self, f):
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

    def get_types(self):
        if(self._logs and len(self._logs) >= 1):
            return self._logs[0].types

    def export(self, target_converter, target_path=None, type_hint=None, merge_types=False, type_filter=None, split_by=None):
        types = set([log.type() for log in self._logs if \
                     ((not type_filter) or (type_filter and isinstance(log.type(), type_filter))) ])
        convert_type = None
        if(len(types) == 1):
            convert_type = list(types)[0]
        elif(len(types) > 1 and not type_hint):
            if(BroLogOptions.interactive):
                print "'%s' has multiple types associated with it:" % log.type().get_bro_path()
                ctr = 1
                for each in types:
                    print '%d: %s' % (ctr, each.type())
                    ctr += 1
                user_sel = int(raw_input('Select a type [1 - %d]: ' % ctr))
                if(user_sel < 1 or user_sel >= ctr):
                    print "Invalid selection."
                    return False
            else:
                return False
        elif(len(types) > 1):
            if not type_hint in types:
                print "Unknown type provided as hint: %s" % type_hint
                return False
            types = set([log.type() for log in self._logs if (log.type() == type_hint)])
            if(len(types) != 1):
                print "Ambiguous type hint?!  Types matched: " + types
                return False
            convert_type = list(types)[0]
        converter = target_converter(target_path, convert_type.names, convert_type.get_bro_path())
        map(converter.convert_row, self.entries(type_filter=convert_type))
        converter.finish()
        return True

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
            translator = log_type._translator
            local_filter = self._filter
            BroLogEntry = self._log_entry_generator(translator, log_type)
            
            if(float(log._sampling) < .9999):
                sampling = float(log._sampling)
                rng = random.random
                field_gen = (l for l in log_fd if rng() < sampling)
            else:
                field_gen = log_fd

            if accumulator:
                for acc in accumulator.keys():
                    log_type._accumulator[acc] = accumulator[acc]

            # Build a few local functions to use. . .
            def accum(x):
                log_type._accumulator[ x[0] ].accumulate(x[1])

            def basic_transform(line):
                line = zip(log_fields, line)
                map(accum, line)

            def filtered_transform(line):
                line = zip(log_fields, line)
                if(local_filter(BroLogEntry(dict(line)))):
                    map(accum, line)

            if not self._filter:
                map(basic_transform, field_gen)
            else:
                map(filtered_transform, field_gen)
            accumulator = log_type._accumulator
        self._accumulator = accumulator
        for acc in self._accumulator.keys():
            self._accumulator[acc].postprocess()
        self._must_compute = False

    def _log_entry_generator(self, translator, log_type):
        names = log_type.names
        class _LogEntry(object):
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
        return _LogEntry

    def entries(self, type_filter=None):
        if not self._logs:
            return False
        
        rlist = []
        for log in self._logs:
            if(type_filter):
                if(log.type() != type_filter):
                    continue
            if(BroLogOptions.verbose):
                print "Processing " + log.path()
            log_type = log.type()
            log_fields = log_type.names
            log_fd = log_type.open(log.path())
            translator = log_type._translator
            BroLogEntry = self._log_entry_generator(translator, log_type)
            if not log_fd:
                continue
            def field_transform(entry):
                return BroLogEntry(dict(zip(log_fields, entry)))
            
            field_gen = log_fd
            if float(log._sampling) < .9999:
                sampling = float(log._sampling)
                rng = random.random
                field_gen = (l for l in log_fd if rng() < sampling)
            field_gen = itertools.imap(field_transform, field_gen)
            if self._filter:
                local_filter = self._filter
                field_gen = itertools.ifilter(local_filter, field_gen)
            rlist.append( field_gen )
        return itertools.chain.from_iterable(rlist)

