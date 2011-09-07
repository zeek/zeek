# See the file "COPYING" in the main distribution directory for copyright.
"""
Describes a specification for the DataSeries log format.  See BroLogSpec for details.
"""
import csv
import os
import re
import shutil
import subprocess
import tempfile

from BroLogOptions import BroLogOptions
from BroLogSpec import BroLogSpec

class DsLogSpec(BroLogSpec):
    """
    Handles loading of DataSeries logfiles.  Note that this class could see a lot of improvement if a Python wrapper comes out for DataSeries.

    See BroLogSpec for further info.
    """
    RE_TYPESPEC = re.compile(r"<!--(.*?)=(.*?)-->")
    RE_PATHSPEC = re.compile(r'<ExtentType name="(.*?)" version="1.0" namespace="bro-ids.org">')  # e.g. <ExtentType name="mime" version="1.0" namespace="bro-ids.org">
    TIME_SCALE = 100000.0
    DS_EXTRACT_DIR = tempfile.mkdtemp()
    EXTRACTED_FILES = dict()

    @staticmethod
    def cleanup():
        """
        Cleans up any temporary files we have extracted DataSeries logs into.
        """
        # print "Cleaning up " + DsLogSpec.DS_EXTRACT_DIR
        shutil.rmtree(DsLogSpec.DS_EXTRACT_DIR)

    def supported(self):
        """
        Checks for the presence of 'ds2txt' on the system.
        """
        return os.system('which ds2txt > /dev/null 2> /dev/null') == 0

    def __init__(self):
        """
        See BroLogSpec for an explanation of what this function does.
        """
        super(DsLogSpec, self).__init__()
        self._opened = None
        self._tpath = None
        self._valid = False

    def _get_translator(self, field_type):
        """
        Since DataSeries records timestamps as integer values (microsecond precision), we need
        to override this function to do a bit of translation work so that we get a happy, sane
        double back when the user asks for it.
        """
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
        """
        If we haven't extracted this file into our temporary directory yet, do so.  Once
        this is done, open the result as a vanilla CSV file and enjoy.
        """
        if path not in DsLogSpec.EXTRACTED_FILES:
            if(BroLogOptions.verbose):
                print "Extracting " + path
            tfd, tpath = tempfile.mkstemp(dir=DsLogSpec.DS_EXTRACT_DIR)
            DsLogSpec.EXTRACTED_FILES[path] = tpath
            os.close(tfd)
            os.system('ds2txt --csv --skip-extent-fieldnames --separator="\t" ' + path + ' > ' + tpath)
        return csv.reader( open(DsLogSpec.EXTRACTED_FILES[path], "rb"), delimiter='\t' )

    def close(self, fd):
        """
        Close the file we opened.
        """
        fd.close()

    def load(self, path):
        """
        Attempts to read and parse bro path and type information from the log file located at 'path'.  If this is successful,
        the file is assumed to be a valid log file and is treated as such.

        ds2txt is used to extract the XML schema from the DataSeries log file.
        """
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
        """
        Tries to read the schema embedded into this particular log file and use it to figure out the bro types and bro path associated
        with this file.  If successful, this function return true and the file is considered valid.
        """
        for line in parse_string.splitlines():
            match = DsLogSpec.RE_TYPESPEC.match(line)
            if match:
                self._fields.append( (match.group(1), match.group(2)) )
                self.names.append( match.group(1) )
                self.types.append( match.group(2) )
                self.translator[match.group(1)] = self._get_translator(match.group(2))
                self.accumulator[match.group(1)] = self._get_accumulator(match.group(2))()
            match = DsLogSpec.RE_PATHSPEC.match(line)
            if match:
                self._bro_log_path = match.group(1)
        if(len(self._bro_log_path) == 0):
            # print "no bro path assignment (e.g. the 'conn' bit of something like 'conn.log' or 'conn.ds') found.  Skipping file..."
            return False
        if(len(self._fields) == 0):
            return False
        return True
    
    def fields(self):
        """
        Returns the field names and types associated with this particular type specification
        """
        return self._fields

