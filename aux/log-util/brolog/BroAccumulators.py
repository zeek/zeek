# See the file "COPYING" in the main distribution directory for copyright.
"""
Contains default accumulator types used by the log library to calculate statistics.
"""

import operator
import math

class BroAccumulators(object):
    """
    Just a container class for a few different default accumulator types.
    """
    class DummyAccumulator(object):
        """
        Used when no other accumulator makes sense for a given data type, or when consistency issues arise during the accumulation 
        / gathering process.  Replaces 'None' as an accumulator type, since the additional if check in the code to determine if an
        accumulator is present experimentally seemed to take longer than just populating the dict with one of these.  I do not
        understand this, but cProfile's results are undeniable.
        """
        def __init__(self):
            """
            Initializes the accumulator.
            """
            pass
        def accumulate(self, entry):
            """
            Accumulates nothing, and by so doing achieves unity with the universe.
            """
            pass
        def postprocess(self):
            """
            Postprocesses the nothing we accumulate.
            """
            pass
        def __str__(self):
            """
            Prints something for nothing.
            """
            return "DummyAccumulator -- Nothing to see here.  Move along."

    class GroupAccumulator(object):
        """
        Used to classify objects and count the number of occurances of each individual element.  For example, a list containing:
        'A', 'A', 'A', 'A', 'B', 'B'  would turn into 'A':4, 'B':2.  Note that these elements can be accessed in sorted order
        via the 'get_index' method defined below.  The __getitem__ method will offer the count of an individual element when
        referenced by name (e.g. result['A'] would return 4, using the example above).

        Note that postprocess is called after all elements have been successfully accumulated.  '-' and '?' are often used as
        NULL characters in bro logfiles, so entries for those characters are purged.  While this might not cooperate with
        custom NULL characters, the intent was to make this library easy to use; forcing the user to post-process data
        gathered seems unintuitive and bad.
        """
        def __init__(self):
            """
            Build an empty set of groups, along with an empty count of the total entries found in the file.
            Although NULL entries are not tallied, we want the statistics to reflect the presence of the element
            in the file as a whole (when presenting in a format resembling that of, say, trace-summary).
            """
            self.groups = dict()
            self.count = 0

        def get_index(self, index, reverse_sort=False):
            """
            Returns the element with the Xth highest frequency in the processed data.  The order in which elements with
            identical frequency are returned is non-deterministic.
            """
            return sorted(self.groups.iteritems(), key=operator.itemgetter(1), reverse=(not reverse_sort))[index]

        def postprocess(self):
            """
            Strip occurances of known NULL entries from our accumulator.  This should probably be done by
            the end-user (or perhaps the log generator), but this works for now.
            """
            if('-' in self.groups.keys()):    # NULL-character, new-style bro logs
                del self.groups['-']
            if('?' in self.groups.keys()):    # NULL-character, old-style bro logs
                del self.groups['?']

        def accumulate(self, entry):
            """
            Checks to see if an entry exists in our groups dictionary.  If it doesn't, then an appropriate entry is created
            and initialized to 0.  If it does, then the number associated with that entry is incremented by one.
            """
            # Using '-' for NULL is nice for reading but sucks for processing.
            if entry not in self.groups:
                self.groups[entry] = 0
            else:
                self.groups[entry] += 1
            self.count += 1
        
        def __len__(self):
            """
            Returns the number of groups found in the accumulated data
            """
            return len(self.groups)

        def __getitem__(self, key):
            """
            Returns the number of times an individual element was found in the data.
            """
            return self.groups[key]

        def __str__(self):
            """
            Prints a few simple statistics for this accumulator.
            """
            return "GroupAccumulator -- accumulated %d times and contains %d groups" % (self.count, len(self.groups))

    # TODO: Revise variance formula -- http://www.cs.berkeley.edu/~mhoemmen/cs194/Tutorials/variance.pdf
    class StatsAccumulator(object):
        """
        Accumulates basic statistics for a series of entries.  Statistics calculated include:
        sum, sum of squares, count, min value, max value, variance, standard deviation
        """
        def __init__(self):
            """
            Initializes a few elements to 0.  Note that sum and sum_of_squares are both calculated as doubles.
            """
            self.sum = 0.0
            self.sum_of_squares = 0.0
            self.count = 0

        def postprocess(self):
            """
            No postprocessing to do.
            """
            pass

        def accumulate(self, entry):
            """
            First tries to convert 'entry' into a float.  If that fails, no values are accumulated.
            Once the number has been successfully converted, the StatsAccumulator will update the statistics it
            has.  Note that the mean, the variance, and the standard deviation are calculated when they are
            requested.
            """
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
            """
            Returns the variance of this numbers accumulated.
            """
            try:
                return (self.sum_of_squares / self.count) - (self.mean ** 2)
            except:
                return 0

        def _mean(self):
            """
            Returns the expected value of the numbers accumulated.
            """
            try:
                return (self.sum / self.count)
            except:
                return 0

        def _std_dev(self):
            """
            Returns the standard deviation of the numbers accumulated.
            """
            try:
                return math.sqrt(self.variance)
            except:
                return 0

        def __str__(self):
            """
            Prints some vital statistics for the data encountered.
            """
            ret_str = "StatsAccumulator -- E[X]=%f, STDDEV(X)=%f, RANGE:[%f, %f]" % (round(self.mean, 3), round(self.std_dev, 3), round(self.min, 3), round(self.max, 3))
            return ret_str

        def __getattr__(self, name):
            """
            Performs calculations and returns appropriate values.  In the case of min / max, the absence of the min / max attributes implies that there were no numbers
            in the list; in this case, we assume the min / max to both be 0.
            """
            # Note: min / max only happen if there were no entries accumulated.
            if(name == 'min'):
                return 0
            if(name == 'max'):
                return 0
            if(name == 'variance'):
                return self._variance()
            if(name == 'mean'):
                return self._mean()
            if(name == 'std_dev'):
                return self._std_dev()
            raise AttributeError

