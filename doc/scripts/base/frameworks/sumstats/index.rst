:orphan:

Package: base/frameworks/sumstats
=================================

The summary statistics framework provides a way to summarize large streams
of data into simple reduced measurements.

:doc:`/scripts/base/frameworks/sumstats/__load__.zeek`


:doc:`/scripts/base/frameworks/sumstats/main.zeek`

   The summary statistics framework provides a way to
   summarize large streams of data into simple reduced
   measurements.

:doc:`/scripts/base/frameworks/sumstats/plugins/__load__.zeek`


:doc:`/scripts/base/frameworks/sumstats/plugins/average.zeek`

   Calculate the average.

:doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek`

   Calculate the number of unique values (using the HyperLogLog algorithm).

:doc:`/scripts/base/frameworks/sumstats/plugins/last.zeek`

   Keep the last X observations.

:doc:`/scripts/base/frameworks/sumstats/plugins/max.zeek`

   Find the maximum value.

:doc:`/scripts/base/frameworks/sumstats/plugins/min.zeek`

   Find the minimum value.

:doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek`

   Keep a random sample of values.

:doc:`/scripts/base/frameworks/sumstats/plugins/std-dev.zeek`

   Calculate the standard deviation.

:doc:`/scripts/base/frameworks/sumstats/plugins/variance.zeek`

   Calculate the variance.

:doc:`/scripts/base/frameworks/sumstats/plugins/sum.zeek`

   Calculate the sum.

:doc:`/scripts/base/frameworks/sumstats/plugins/topk.zeek`

   Keep the top-k (i.e., most frequently occurring) observations.
   
   This plugin uses a probabilistic algorithm to count the top-k elements.
   The algorithm (called Space-Saving) is described in the paper Efficient
   Computation of Frequent and Top-k Elements in Data Streams", by
   Metwally et al. (2005).

:doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek`

   Calculate the number of unique values.

:doc:`/scripts/base/frameworks/sumstats/non-cluster.zeek`


