# See the file "COPYING" in the main distribution directory for copyright.
"""
This module contains a small logical BroLogFile wrapper for BroLogSpec
"""

from BroLogUtil import BroLogUtil

class BroLogFile(object):
    """
    A small wrapper for a LogSpec, a file path, and a validity check.

    Beyond the above, this class really isn't responsible for much.
    """
    def __init__(self, path, sampling=1.0):
        """
        Initializes a BroLogSpec based on the extension of the file passed as an
        argument.  'sampling' is the probability of processing a given row; this
        can lead to faster processing of large files, but naturally reduces the
        accuracy of reported statistics.

        Additionally, note that providing large values of 'sampling' may actually 
        yield longer run times than processing all rows.
        """
        self._path = path
        self._field_info = BroLogUtil.get_field_info(path)()
        if(self._field_info.supported()):
            self._valid = self._field_info.load(path)
        else:
            self._valid = False
        self.sampling = sampling

    def type(self):
        """
        Returns the typespec for this log file.
        """
        return self._field_info

    def type_id(self):
        """
        Returns the typespec's ID for this log file.  Largely provided for
        convenience's sake.
        """
        return self._field_info.id()

    def valid(self):
        """
        True if the log file was parsed and loaded successfully, and false
        otherwise.
        """
        return self._valid

    def path(self):
        """
        The filesystem path associated with this file.
        """
        return self._path

    def bro_path(self):
        """
        The logical (bro) path associated with this file (e.g. 'conn' in the case of most conn.log files).
        """
        return self._field_info.get_bro_path()

