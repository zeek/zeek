import operator
import math

class BroAccumulators(object):
    class DummyAccumulator(object): 
        def __init__(self):
            self.count = 0
        def accumulate(self, entry):
            self.count += 1
        def postprocess(self):
            pass
        def __str__(self):
            return "DummyAccumulator -- accumulated %d times" % self.count

    class GroupAccumulator(object):
        def __init__(self):
            self.groups = dict()
            self.count = 0

        def get_index(self, index):
            return sorted(self.groups.iteritems(), key=operator.itemgetter(1), reverse=True)[index]

        def postprocess(self):
            if('-' in self.groups.keys()):
                del self.groups['-']

        def accumulate(self, entry):
            # Using '-' for NULL is nice for reading but sucks for processing.
            if entry not in self.groups:
                self.groups[entry] = 0
            else:
                self.groups[entry] += 1
            self.count += 1
        
        def __getitem__(self, key):
            return self.groups[key]

        def __str__(self):
            return "GroupAccumulator -- accumulated %d times and contains %d groups" % (self.count, len(self.groups))

    # TODO: Revise variance formula -- http://www.cs.berkeley.edu/~mhoemmen/cs194/Tutorials/variance.pdf
    class StatsAccumulator(object):
        def __init__(self):
            self.sum = 0.0
            self.sum_of_squares = 0.0
            self.count = 0

        def postprocess(self):
            pass

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

