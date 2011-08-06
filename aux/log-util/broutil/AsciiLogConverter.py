import csv

class AsciiLogConverter(object):
    def __init__(self, path, names, log_path):
        self._path = path
        self._names = names
        self._log_path = log_path
        if(self._path):
            self._fd = open(self._path, 'wb')
        else:
            self._fd = open(log_path + '.log.converted', 'wb')
        self._writer = csv.writer(self._fd, delimiter='\t')
    
    def _do_convert(self, entry):
        if not entry:
            return '-'
        return str(entry)
            
    def convert_row(self, entry):
        row_entries = [self._do_convert(entry[name]) for name in self._names]
        self._writer.writerow(row_entries)

    def finish(self):
        self._fd.close()

