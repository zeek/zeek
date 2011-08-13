# See the file "COPYING" in the main distribution directory for copyright.
"""
Main user interface for the log library code.
"""
import os

from BroLogUtil import *
from BroLogFile import *
from BroLogGenerator import *

class SimpleLogManager(object):
    """
    This class handles loading / managing a *single* log file.  It acts as a 
    simple wrapper for BroLogManager.

    More a convenience class than anything else.  This class does not segregate
    by path or type (beyond what the BroLogManager it uses will).  Instead, 
    it's meant to offer a simple, iterable interface for *all* the log entries 
    in a given file.
    """
    def load(self, path, sampling=1.0):
        """
        This will pass a path off to the BroLogManager's load
        function to load.
        """
        if not isinstance(path, str) and len(path) > 1:
            raise ValueError("SimpleLogManager only works on single log files")
        self._manager = BroLogManager(sampling=sampling)
        self._manager.load(path)

    def set_filter(self, function):
        """
        This will apply a filter to all entries before they
        are sampled / parsed.
        """
        if(len(self._manager.all_generators()) <= 0):
            raise ValueError("Can't apply a filter before loading log files")
        self._manager.all_generators()[0].set_filter(function)
        return True

    def entries(self):
        """
        Iterates through all the entries in the opened log file(s)
        """
        return self._manager.all_entries()     

    def get(self):
        """
        Pulls the first available generator (ideally the *only*
        generator) and offers it as an interface to do an export,
        gather statistics, etc.
        """
        return self._manager.all_generators()[0]

    def __iter__(self):
        """
        Iterates through all the entries in the opened log file(s)
        """
        return self.entries()

    def __len__(self):
        """
        Iterates through ALL THE ENTRIES in the opened log file(s) and counts 
        how many there are (note that filters / samples are applied before
        rows are counted)
        """
        ctr = 0
        for entry in self:
            ctr += 1
        return ctr

class BroLogManager(object):
    """
    This class handles loading and managing a set of log paths.  It splices them
    into logical sets (via the internal bro path), constructs appropriate 
    generators, and offers a very simple interface for the user to use the logs.
    """
    def __init__(self, sampling=1.0):
        """
        _path is the path given to the BroLogManager to load.  If _path is a 
        file, it will be added to the list of working log files.  If _path is a
        directory, it (and all of its subdirectories) will be scanned.  A file 
        extension filter will be applied first; for usable file extensions, 
        check out __init__.py and regster_type().  Each file found will be 
        tested for validity (when the BroLogFile is constructed; see 
        self._logobj in open(self, path) below).
        
        _total_count is the total number of files scanned, and _success_count is
        the number of files that are believed to be valid log files.
        """
        self._path = None
        self._logfiles = []
        self._logobj = []
        self._total_count = 0
        self._success_count = 0
        self._sampling = sampling

    def load(self, paths):
        """
        Load all the paths in the iterable object provided to us.

        Note that if path is a string, it is converted to a list with a single
        element before being processed (thanks Gregor).
        """
        if(isinstance(paths, str)):
            paths = [ paths ]
        map(self.open, paths)

    def open(self, path):
        """
        Opens all the files associated with 'path'.

        If path is a directory, it is first converted into a list of *all files*
        in the directory (along with all of its subdirectories).  For each 
        discovered logfile, an extension filter is first applied.  Assuming the 
        file's extension is known, it is passed to a LogSpec object for 
        validation.  If the LogSpec object believes the object to be valid (as 
        tested in the BroLogFile constructor), BroLogManager then inserts it 
        into a list based on its bro path name.  Once this process is complete,
        BroLogManager has a list of log files associated with each unique 
        internal bro path (e.g. 'conn', 'ftp', 'weird', etc), which it uses to 
        build a set of BroLogGenerators.  The BroLogGenerator objects offer the
        user a simple way to interact with all the files associated with a
        particular path.
        """
        self._path = path
        if(os.path.isdir(path)):
            os.path.walk(path, lambda arg, dirname, fnames: arg.extend( [ os.path.join(os.path.abspath(dirname), f) for f in fnames ] ), self._logfiles)
        else:
            self._logfiles.append(path)
        self._logfiles = list(set(self._logfiles))  # Remove duplicates
        self._logfiles = [f for f in self._logfiles if BroLogUtil.supports(f) ]  # Only keep supported file types
        self._total_count = len(self._logfiles)
        self._logobj = [ BroLogFile(f, sampling=self._sampling) for f in self._logfiles ]
        self._logobj = [ f for f in self._logobj if f.valid() ]  # Only keep file types that load successfully
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
        """
        Returns a BroLogGenerator for a given path.
        """
        if key in self._log_gen:
            return self._log_gen[key]
        return None

    def all_generators(self):
        """
        This will offer a list of all the generators offered by the 
        BroLogManager.  
        
        This is closely related to all_entries below, except that this should 
        allow the user to iterate through the generators and request statistics,
        exporting, etc. from the generators directly.
        """
        gen_list = [self._log_gen[key] for key in self._log_gen.keys()]
        return gen_list

    def all_entries(self):
        """
        This will offer a generator which will iterate over *every* row of 
        *every* file loaded by the BroLogManager.

        If that sounds like a lot of data... well... that's because it normally 
        is.  This is mostly offered as a simple way for the SimpleLogManager 
        thingy to offer a quick way to work with a single file / all entries in
        all files.
        """
        gen_list = [self._log_gen[key].entries() for key in self._log_gen.keys()]
        return itertools.chain.from_iterable(gen_list)

    def __getitem__(self, key):
        """
        Returns a BroLogGenerator for a given path; functionally equivalent to 
        get() above.
        """
        return self.get(key)

    def print_stats(self):
        """
        Print some basic statistics about the number of files loaded, number 
        of unique internal bro paths discovered, etc.  Meant to act as a 
        simple sanity check.
        """
        print "Found " + str(self._total_count) + " logfiles."
        print "Successfully loaded " + str(self._success_count) + " logfiles."
        print "Identified " + str(self._type_count) + " unique bro paths."

