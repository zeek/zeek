import atexit
import bz2
import csv
import gzip
import hashlib
import itertools
import math
import os
import os.path
import re
import shutil
import subprocess
import tempfile

class LogOptions(object):
    verbose = False

class BroLogGenerator(object):
    def __init__(self, log_list):
        self._logs = log_list
        self._filter = None
        self._must_compute = True

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
            return self._logs[0]._names

    def get_types(self):
        if(self._logs and len(self._logs) >= 1):
            return self._logs[0]._types

    def compute_stats(self):
        if not self._logs:
            return False
        accumulator = None
        for log in self._logs:
            log_type = log.type()
            log_fields = log_type._names
            log_fd = log_type.open(log.path())
            if accumulator:
                log_type._accumulator = accumulator
            def accum(line):
                line = zip(log_fields, line)
                map(lambda x: log_type._accumulator[ x[0] ].accumulate(x[1]), line)
            map(accum, log_fd)
            accumulator = log_type._accumulator
        self._accumulator = accumulator
        self._must_compute = False

    def entries(self):
        if not self._logs:
            return False
        
        rlist = []
        for log in self._logs:
            log_type = log.type()
            log_fields = log_type._names
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
                    return log_type._types

            def field_transform(x):
                return BroLogEntry(dict(zip(log_fields, x)))

            if not log_fd:
                continue
            rlist.append(itertools.imap(field_transform, log_fd))
        return itertools.chain.from_iterable(rlist)

class BroLogFile(object):
    def __init__(self, path):
        self._path = path
        self._field_info = BroLogManager.get_field_info(path)()
        self._valid = self._field_info.load(path)
        self._fd = None

    def type(self):
        return self._field_info

    def type_id(self):
        return self._field_info.id()

    def open(self):
        if(self._valid):
            self._fd = self._field_info.open(path)
            return self._fd
        return None

    def valid(self):
        return self._valid

    def path(self):
        return self._path

    def bro_path(self):
        return self._field_info.get_bro_path()

class BroLogManager(object):
    logtypes = dict()
    EXT_EXPR = re.compile(r"[^/].*?\.(.*)$")

    @staticmethod
    def supports(path):
        base, fname = os.path.split(path)
        return BroLogManager.get_ext(fname) in BroLogManager.logtypes

    @staticmethod
    def get_field_info(path):
        base, fname = os.path.split(path)
        return BroLogManager.logtypes[ BroLogManager.get_ext(fname) ]

    @staticmethod
    def get_ext(path):
        m = BroLogManager.EXT_EXPR.search(path)
        if(m):
            return m.group(1)
        return None

    @staticmethod
    def register_type(file_ext, target):
        BroLogManager.logtypes[file_ext] = target

    def __init__(self):
        self._path = None
        self._logfiles = []
        self._logobj = []
        self._total_count = 0
        self._success_count = 0

    def load(self, paths):
        map(self.open, paths)

    def open(self, path):
        self._path = path
        if(os.path.isdir(path)):
            os.path.walk(path, lambda arg, dirname, fnames: arg.extend( [ os.path.join(os.path.abspath(dirname), f) for f in fnames ] ), self._logfiles)
        else:
            self._logfiles.append(path)
        self._logfiles = list(set(self._logfiles))  # Remove duplicates
        self._logfiles = [f for f in self._logfiles if BroLogManager.supports(f) ]  # Only keep supported file types
        self._total_count = len(self._logfiles)
        self._logobj = [ BroLogFile(f) for f in self._logfiles ]
        self._logobj = [ f for f in self._logobj if f.valid() ]
        self._success_count = len(self._logobj)
        # self._fields = [ obj._field_info for obj in self._logobj ]
        # self._fields = set(self._fields)
        # self._type_count = len(self._fields)
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

class BroAccumulators(object):
    class DummyAccumulator(object): 
        def __init__(self):
            self.count = 0
        def accumulate(self, entry):
            self.count += 1
        def __str__(self):
            return "DummyAccumulator -- accumulated %d times" % self.count

    class GroupAccumulator(object):
        def __init__(self):
            self.groups = dict()
            self.count = 0

        def accumulate(self, entry):
            # Using '-' for NULL is nice for reading but sucks for processing.
            if entry == '-':
                return
            if entry not in self.groups:
                self.groups[entry] = 0
            else:
                self.groups[entry] += 1
            self.count += 1

        def __str__(self):
            return "GroupAccumulator -- accumulated %d times and contains %d groups" % (self.count, len(self.groups))

    # TODO: Revise variance formula -- http://www.cs.berkeley.edu/~mhoemmen/cs194/Tutorials/variance.pdf
    class StatsAccumulator(object):
        def __init__(self):
            self.sum = 0.0
            self.sum_of_squares = 0.0
            self.count = 0

        def accumulate(self, entry):
            try:
                x = float(entry)
            except:
                return
            self.sum += x
            self.sum_of_squares += x ** 2
            self.count += 1

            # Hack to avoid the additional 'if' condition
            try:
                if x < self.min:
                    self.min = x
            except:
                self.min = x

            # Hack to avoid the additional 'if' condition
            try:
                if x > self.max:
                    self.max = x
            except:
                self.max = x

        def _variance(self):
            return (self.sum_of_squares / self.count) - (self.mean ** 2)

        def _mean(self):
            return (self.sum / self.count)

        def _std_dev(self):
            return math.sqrt(self.variance)

        def __str__(self):
            ret_str = "StatsAccumulator -- E(X)=%f, STDDEV(X)=%f, RANGE:[%f, %f]" % (round(self.mean, 3), round(self.std_dev, 3), round(self.min, 3), round(self.max, 3))
            return ret_str

        def __getattr__(self, name):
            if(name == 'variance'):
                return self._variance()
            if(name == 'mean'):
                return self._mean()
            if(name == 'std_dev'):
                return self._std_dev()
            raise AttributeError

class BaseLogSpec(object):
    def __init__(self):
        self._fields = []
        self._names = []
        self._bro_log_path = ""
        self._valid = False
        self._translator = dict()

    def _get_accumulator(self, field_type):
        # Basic numeric accumulator: mean, variance, min, max
        if(field_type == 'double' or field_type == 'int' or field_type == 'count' or field_type == 'counter'):
            return BroAccumulators.StatsAccumulator

        # These types should be classified by group.
        if(field_type == 'port' or field_type == 'addr' or field_type == 'net' or field_type == 'subnet' or field_type == 'string'):
            return BroAccumulators.GroupAccumulator

        # Other types aren't supported as of yet.
        return BroAccumulators.DummyAccumulator

    def _get_translator(self, field_type):
        if(field_type == 'double' or field_type == 'time' or field_type == 'interval'):
            def get_val(val):
                try:
                    return float(val)
                except:
                    return None
        elif(field_type == 'int' or field_type == 'count' or field_type == 'counter'):
            def get_val(val):
                try:
                    return int(val)
                except:
                    return None
        else:
            def get_val(val):
                return val
        return get_val

    def get_bro_path(self):
        return self._bro_log_path

    def id(self):
        m = hashlib.md5()
        m.update(str(self._bro_log_path))
        m.update(str(self._fields))
        return m.hexdigest()

    def valid(self):
        return self._valid

    def __str__(self):
        return (self.id() + " : " + self._bro_log_path + " -- " + str(self._fields))

    def __repr__(self):
        return (self.id() + " : " + self._bro_log_path + " -- " + str(self._fields))

    def __eq__(self, other):
        if issubclass(other.__class__, BaseLogSpec):
            return self.id() == other.id()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.id())

class DsLogSpec(BaseLogSpec):
    RE_TYPESPEC = re.compile(r"<!--(.*?)=(.*?)-->")
    RE_PATHSPEC = re.compile(r'<ExtentType name="(.*?)" version="1.0" namespace="bro-ids.org">')  # e.g. <ExtentType name="mime" version="1.0" namespace="bro-ids.org">
    TIME_SCALE = 100000.0
    DS_EXTRACT_DIR = tempfile.mkdtemp()
    EXTRACTED_FILES = dict()

    @staticmethod
    def cleanup():
        print "Cleaning up " + DsLogSpec.DS_EXTRACT_DIR
        shutil.rmtree(DsLogSpec.DS_EXTRACT_DIR)

    def __init__(self):
        self._fields = []
        self._names = []
        self._types = []
        self._bro_log_path = ""
        self._opened = None
        self._tpath = None
        self._valid = False
        self._translator = dict()
        self._accumulator = dict()

    def _get_translator(self, field_type):
        if(field_type == 'double'):
            def get_val(val):
                try:
                    return float(val)
                except:
                    return None
        elif(field_type == 'time' or field_type == 'interval'):
            def get_val(val):
                try:
                    return float(val) / DsLogSpec.TIME_SCALE
                except:
                    return None
        elif(field_type == 'int' or field_type == 'count' or field_type == 'counter'):
            def get_val(val):
                try:
                    return int(val)
                except:
                    return None
        else:
            def get_val(val):
                return val
        return get_val

    def open(self, path):
        if path not in DsLogSpec.EXTRACTED_FILES:
            if(LogOptions.verbose):
                print "Extracting " + path
            tfd, tpath = tempfile.mkstemp()
            DsLogSpec.EXTRACTED_FILES[path] = tpath
            os.close(tfd)
            os.system('ds2txt --csv --skip-extent-fieldnames --separator="\t" ' + path + ' > ' + tpath)
        return csv.reader( open(DsLogSpec.EXTRACTED_FILES[path], "rb"), delimiter='\t' )

    def close(self, fd):
        fd.close()

    def load(self, path):
        xml_str = ""
        # This will pull ALL schema definitions out of the DataSeries log file.  Our comment hack works because our schema *should* be the only thing defined
        # within DataSeries that has comment tags of the form defined above; if this assumption does not hold, the typespec will be incorrect.
        tload = subprocess.Popen(['ds2txt', '--skip-index', '--select', "DataSeries: XmlType", "*", str(path)], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        res = tload.communicate()
        if(len(res[0]) > 0):
            xml_str = reduce(lambda x, y: x + y, res[0])
        else:
            # print "Could not load: " + path
            self._valid = False
            return False
        if(self.parse(xml_str)):
            self._valid = True
            return True
        self._valid = False
        return False

    def parse(self, parse_string):
        for line in parse_string.splitlines():
            m = DsLogSpec.RE_TYPESPEC.match(line)
            if m:
                self._fields.append( (m.group(1), m.group(2)) )
                self._names.append( m.group(1) )
                self._types.append( m.group(2) )
                self._translator[m.group(1)] = self._get_translator(m.group(2))
                self._accumulator[m.group(1)] = self._get_accumulator(m.group(2))()
            m = DsLogSpec.RE_PATHSPEC.match(line)
            if m:
                self._bro_log_path = m.group(1)
        if(len(self._bro_log_path) == 0):
            # print "no bro path assignment (e.g. the 'conn' bit of something like 'conn.log' or 'conn.ds') found.  Skipping file..."
            return False
        if(len(self._fields) == 0):
            return False
        return True
    
    def types(self):
        return self._fields

class AsciiLogSpec(BaseLogSpec):
    RE_TYPESPEC = re.compile(r"\s*#(.*?)\n?")  # Pull out everything after a comment character
    RE_PATHSPEC = re.compile(r"\s*#\s*path:'(.*)'")  # Pull out the logfile path name (as defined by bro; this is *NOT* the filesystem path)
    RE_SEPARATOR = re.compile(r"\s*#\s*separator:'(.*)'")  # Pull out the separator character
    RE_TYPE_ENTRY = re.compile(r"(.*)=(.*)")  # Extract FIELD=BRO_TYPE

    def __init__(self):
        self._fields = []
        self._names = []
        self._types = []
        self._bro_log_path = ""
        self._separator = ""
        self._valid = False
        self._translator = dict()
        self._accumulator = dict()

    def raw_open(self, path):
        if(BroLogManager.get_ext(path) == 'log.gz'):
            ascii_file = gzip.GzipFile(path)
        elif(BroLogManager.get_ext(path) == 'log.bz2'):
            ascii_file = bz2.BZ2File(path)
        else:
            ascii_file = open(path)
        return ascii_file
    
    def _open_filter(self, line):
        return line[0][0] != '#'

    def open(self, path):
        if(BroLogManager.get_ext(path) == 'log.gz'):
            ascii_file = gzip.GzipFile(path)
        elif(BroLogManager.get_ext(path) == 'log.bz2'):
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
        self._names = [ entry.group(1) for entry in m ]
        self._types = [ entry.group(2) for entry in m ]
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

BroLogManager.register_type('log', AsciiLogSpec)
BroLogManager.register_type('log.gz', AsciiLogSpec)
BroLogManager.register_type('log.bz2', AsciiLogSpec)
BroLogManager.register_type('ds', DsLogSpec)

atexit.register(DsLogSpec.cleanup)

