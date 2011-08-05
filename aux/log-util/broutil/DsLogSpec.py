import csv
import os
import re
import shutil
import subprocess
import tempfile

from BroLogOptions import *
from BroLogSpec import *

class DsLogSpec(BroLogSpec):
    RE_TYPESPEC = re.compile(r"<!--(.*?)=(.*?)-->")
    RE_PATHSPEC = re.compile(r'<ExtentType name="(.*?)" version="1.0" namespace="bro-ids.org">')  # e.g. <ExtentType name="mime" version="1.0" namespace="bro-ids.org">
    TIME_SCALE = 100000.0
    DS_EXTRACT_DIR = tempfile.mkdtemp()
    EXTRACTED_FILES = dict()

    @staticmethod
    def cleanup():
        print "Cleaning up " + DsLogSpec.DS_EXTRACT_DIR
        shutil.rmtree(DsLogSpec.DS_EXTRACT_DIR)

    def supported(self):
        return os.system('which ds2txt > /dev/null 2> /dev/null') == 0

    def __init__(self):
        self._fields = []
        self.names = []
        self.types = []
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
            if(BroLogOptions.verbose):
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
                self.names.append( m.group(1) )
                self.types.append( m.group(2) )
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

