import hashlib

from BroAccumulators import *

class BroLogSpec(object):
    def __init__(self):
        self._fields = []
        self.names = []
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
        if issubclass(other.__class__, BroLogSpec):
            return self.id() == other.id()
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.id())
