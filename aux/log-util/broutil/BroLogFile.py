from BroLogUtil import *

class BroLogFile(object):
    def __init__(self, path, sampling=1.0):
        self._path = path
        self._field_info = BroLogUtil.get_field_info(path)()
        self._valid = self._field_info.load(path)
        self._fd = None
        self._sampling = sampling

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

