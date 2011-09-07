# See the file "COPYING" in the main distribution directory for copyright.
"""
Processes log files and turns them into something easy for the script writer to manipulate / use.  Three things are currently
supported:
export -- transform log files from one format into another
iterate -- iterate through all the loaded log files, one line at a time
statistics -- iterate through all the loaded log files and compute statistics, which are available via get_stats()
"""

import itertools
import random

from BroLogOptions import BroLogOptions
from BroAccumulators import BroAccumulators

class BroLogGenerator(object):
    """
    BroLogGenerator is a utility class designed to act as a utility class for working with Bro log files.  It provides a generator
    for BroLogEntries (entries()), an optional per-row filter (via 'set_filter'), sampling (applied *before* any filter in order
    to save processing time), export support, and statistics support.
    """
    def __init__(self, log_list):
        """
        Configures the BroLogGenerator to operate on a set of log files, specified as BroLogFile objects.
        self._filter -- Function is called on a given line of input and only processed if this function returns True.
                        Note that this function is expected to take a single _LogEntry as its sole argument, and is
                        applied *after* sampling (e.g. .2 sampling --> 20% of log entries are processed by the filter).
        self._must_compute -- If this is true, statistics will be computed on the entire data set the first time get_stats() is
                              called on an object.
        self.accumulator -- Used as a temporary variable to pass between log files as statistics are computed.
        """
        self._logs = log_list
        self._filter = None
        self._must_compute = True
        self.accumulator = None

    def set_filter(self, local_filter):
        """
        Note that a filter function must accept a single argument, and should expect that argument to be of type _LogEntry.  See
        the _log_entry_generator below for more details.
        """
        self._filter = local_filter

    def get_stats(self, field):
        """
        Returns an accumulator object for a given field.  This object can be used to obtain various statistics about the field;
        see the BroAccumulators module for details.
        """
        if(self._must_compute):
            self.compute_stats()
        if(self._must_compute):
            return None  # Computation failed for some reason
        return self.accumulator[field]

    def export(self, target_converter, target_path=None, type_hint=None, merge_types=False, type_filter=None, split_by=None):
        """
        Takes a converter (see AsciiLogConverter) and uses it to convert *all currently loaded* logfiles into a single log file.
        Note that any filter is applied to the export process; if this is not desired, set_filter(None) to remove the filter.
        """
        types = set([log.type() for log in self._logs if \
                     ((not type_filter) or (type_filter and isinstance(log.type(), type_filter))) ])
        convert_type = None
        if(len(types) == 1):
            convert_type = list(types)[0]
        elif(len(types) > 1):
            if not type_hint in types:
                print "Unknown type provided as hint: %s" % type_hint
                return False
            types = set([log.type() for log in self._logs if (log.type() == type_hint)])
            if(len(types) != 1):
                print "Ambiguous type hint?!  Types matched: " + types
                return False
            convert_type = list(types)[0]
        converter = target_converter(target_path, convert_type.fields(), convert_type.get_bro_path())
        map(converter.convert_row, self.entries(type_filter=convert_type))
        converter.finish()
        try:
            del converter
        except:
            pass
        return True

    def compute_stats(self):
        """
        Iterates through all specified log files and calls the accumulator for each field in a given row.
        Note that any filter is applied to this process; if this is not desired, set_filter(None) to remove the filter.
        get_stats() will automatically call this function if statistics have not yet been computed.
        """
        if not self._logs:
            return False
        accumulator = None
        for log in self._logs:
            if(BroLogOptions.verbose):
                print "Processing " + log.path()
            log_type = log.type()
            log_fields = log_type.names
            log_fd = log_type.open(log.path())
            translator = log_type.translator
            formatter = log_type.formatter
            local_filter = self._filter
            BroLogEntry = self._log_entry_generator(translator, log_type, formatter)
            
            if(float(log.sampling) < .9999):
                sampling = float(log.sampling)
                rng = random.random
                field_gen = (l for l in log_fd if rng() < sampling)
            else:
                field_gen = log_fd

            if accumulator:
                for acc in accumulator.keys():
                    log_type.accumulator[acc] = accumulator[acc]

            # Build a few local functions to use. . .
            def accum(x):
                log_type.accumulator[ x[0] ].accumulate(x[1])

            def basic_transform(line):
                line = zip(log_fields, line)
                map(accum, line)

            def filtered_transform(line):
                line = zip(log_fields, line)
                if(local_filter(BroLogEntry(line))):
                    map(accum, line)

            if not self._filter:
                map(basic_transform, field_gen)
            else:
                map(filtered_transform, field_gen)
            accumulator = log_type.accumulator
        self.accumulator = accumulator
        for acc in self.accumulator.keys():
            self.accumulator[acc].postprocess()
        self._must_compute = False

    def _log_entry_generator(self, translator, log_type, formatter):
        """
        Builds a _LogEntry class for the BroLogGenerator to use.  This is done largely as an optimization;
        because this class is being constructed millions of times, the additional __init__ arguments and
        construction overhead become a problem.

        Note also that, while this class *does* support access via 'entry.ts', fields like 'entry.id.orig_p'
        are not supported because they break Python's naming conventions.  In these instances, entry['id.orig_p']
        must be used to access / manipulate these fields.
        """
        names = log_type.names
        name2idx = dict()
        i=0
        for n in names:
            name2idx[n] = i
            i+=1
        class _LogEntry(object):
            """
            An individual log entry.  Supports access in classical dict form (entry['ts']) or in classical
            derived attribute fashion (entry.ts).  Note, however, that certain fields may break Python naming 
            conventions and are not available as attributes.
            """
            @staticmethod
            def type():
                """
                Returns the BroLogSpec associated with the current LogEntry
                """
                return log_type

            @staticmethod
            def types():
                """
                Returns the field types for the given LogEntry.
                """
                return log_type.types

            @staticmethod
            def names():
                """
                Returns the field names for the given LogEntry.
                """
                return log_type.names

            def __init__(self, vals):
                """
                Quick array copy.
                """
                self._vals = vals

            def __getattr__(self, name):
                """
                Translates the value into something usable by consulting the translator specified as an
                argument to the _log_entry_generator function above.  Ideally, keeping this stuff local
                in scope should limit time spent looking stuff up in 'self'.
                
                Attributes are translated lazily (e.g. as they're loaded).  There is no error checking
                here because of the speed hit we take; as such, it's very possible for this function to
                throw a KeyError.
                """
                self.__dict__[name] = translator[name](self._vals[name2idx[name]]) 
                return self.__dict__[name]
        
            def __getitem__(self, name):
                """
                Translates and returns the attribute denoted by 'name'.  This method can be used to access
                field names that break Python naming conventions (e.g. 'id.orig_p').
                """
                return translator[name](self._vals[name2idx[name]])
            
            def render(self, name):
                """
                Pushes the field referenced by 'name' through the formatter and returns the resulting
                string.
                """
                tVal = translator[name](self._vals[name2idx[name]])
                if(tVal):
                    return formatter[name] % tVal
                return BroLogOptions.null_string 

        return _LogEntry

    def entries(self, type_filter=None):
        """
        This function returns a generator that can be used to iterate through all the entries in *all* loaded log files.
        The order in which the log files are traversed is essentially non-deterministic for the moment.  This could change
        in the future.
        """
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
            translator = log_type.translator
            formatter = log_type.formatter
            BroLogEntry = self._log_entry_generator(translator, log_type, formatter)
            if not log_fd:
                continue
            def field_transform(entry):
                return BroLogEntry(entry)
            
            field_gen = log_fd
            if float(log.sampling) < .9999:
                sampling = float(log.sampling)
                rng = random.random
                field_gen = (l for l in log_fd if rng() < sampling)
            field_gen = itertools.imap(field_transform, field_gen)
            if self._filter:
                local_filter = self._filter
                field_gen = itertools.ifilter(local_filter, field_gen)
            rlist.append( field_gen )
        return itertools.chain.from_iterable(rlist)

