# See the file "COPYING" in the main distribution directory for copyright.
"""
Very basic converter.  Kept simple partially for the sake of example, and partially because there's no complex logic that really needs
to go in here.
"""
import csv

class AsciiLogExporter(object):
    """
    Converts a series of log entries into a single, coherent whole.  Additionally acts as a way to enforce
    common formatting on all log formats; the idea is to use this converter to generate baseline entries
    for btest.
    """
    def __init__(self, path, fields, log_path):
        """
        Sets up the ASCII exporter.  Opens the appropriate output file; if path is not None, then the
        provided path is used.  Otherwise, the internal log path with a '.log.converted' suffix is
        used as the target.  Note that this file is created in the current working directory, and is
        overwritten if it already exists...
        """
        self._path = path
        self._fields = fields
        self._log_path = log_path
        if(self._path):
            self._fd = open(self._path, 'wb')
        else:
            self._fd = open(log_path + '.log.converted', 'wb')
        self._writer = csv.writer(self._fd, delimiter='\t')
    
    def _do_convert(self, entry, entry_type):
        """
        Converts a single entry to an ASCII-suitable format.
        """
        if not entry:
            return '-'
        return str(entry)
            
    def convert_row(self, entry):
        """
        Converts an entire row to a Python list, which is passed to csv.writerow for conversion into an actual
        entry in our target file.
        """
        row_entries = [self._do_convert(entry[field[0]], field[1]) for field in self._fields]
        self._writer.writerow(row_entries)

    def finish(self):
        """
        Closes our file once the conversion is finished.
        """
        self._fd.close()

