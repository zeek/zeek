:tocdepth: 3

base/frameworks/sumstats/main.zeek
==================================
.. bro:namespace:: SumStats

The summary statistics framework provides a way to
summarize large streams of data into simple reduced
measurements.

:Namespace: SumStats

Summary
~~~~~~~
Types
#####
===================================================== ========================================================================
:bro:type:`SumStats::Calculation`: :bro:type:`enum`   Type to represent the calculations that are available.
:bro:type:`SumStats::Key`: :bro:type:`record`         Represents a thing which is having summarization
                                                      results collected for it.
:bro:type:`SumStats::Observation`: :bro:type:`record` Represents data being added for a single observation.
:bro:type:`SumStats::Reducer`: :bro:type:`record`     Represents a reducer.
:bro:type:`SumStats::Result`: :bro:type:`table`       Type to store a table of results for multiple reducers indexed by
                                                      observation stream identifier.
:bro:type:`SumStats::ResultTable`: :bro:type:`table`  Type to store a table of sumstats results indexed by keys.
:bro:type:`SumStats::ResultVal`: :bro:type:`record`   Result calculated for an observation stream fed into a reducer.
:bro:type:`SumStats::SumStat`: :bro:type:`record`     Represents a SumStat, which consists of an aggregation of reducers along
                                                      with mechanisms to handle various situations like the epoch ending
                                                      or thresholds being crossed.
===================================================== ========================================================================

Redefinitions
#############
================================================= =
:bro:type:`SumStats::Reducer`: :bro:type:`record` 
================================================= =

Functions
#########
===================================================== =================================================================
:bro:id:`SumStats::create`: :bro:type:`function`      Create a summary statistic.
:bro:id:`SumStats::key2str`: :bro:type:`function`     Helper function to represent a :bro:type:`SumStats::Key` value as
                                                      a simple string.
:bro:id:`SumStats::observe`: :bro:type:`function`     Add data into an observation stream.
:bro:id:`SumStats::request_key`: :bro:type:`function` Dynamically request a sumstat key.
===================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: SumStats::Calculation

   :Type: :bro:type:`enum`

      .. bro:enum:: SumStats::PLACEHOLDER SumStats::Calculation

      .. bro:enum:: SumStats::AVERAGE SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/average.zeek` is loaded)


         Calculate the average of the values.

      .. bro:enum:: SumStats::HLL_UNIQUE SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)


         Calculate the number of unique values.

      .. bro:enum:: SumStats::LAST SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/last.zeek` is loaded)


         Keep last X observations in a queue.

      .. bro:enum:: SumStats::MAX SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/max.zeek` is loaded)


         Find the maximum value.

      .. bro:enum:: SumStats::MIN SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/min.zeek` is loaded)


         Find the minimum value.

      .. bro:enum:: SumStats::SAMPLE SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek` is loaded)


         Get uniquely distributed random samples from the observation
         stream.

      .. bro:enum:: SumStats::VARIANCE SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/variance.zeek` is loaded)


         Calculate the variance of the values.

      .. bro:enum:: SumStats::STD_DEV SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/std-dev.zeek` is loaded)


         Calculate the standard deviation of the values.

      .. bro:enum:: SumStats::SUM SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sum.zeek` is loaded)


         Calculate the sum of the values.  For string values,
         this will be the number of strings.

      .. bro:enum:: SumStats::TOPK SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/topk.zeek` is loaded)


         Keep a top-k list of values.

      .. bro:enum:: SumStats::UNIQUE SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek` is loaded)


         Calculate the number of unique values.

   Type to represent the calculations that are available.  The calculations
   are all defined as plugins.

.. bro:type:: SumStats::Key

   :Type: :bro:type:`record`

      str: :bro:type:`string` :bro:attr:`&optional`
         A non-address related summarization or a sub-key for
         an address based summarization. An example might be
         successful SSH connections by client IP address
         where the client string would be the key value.
         Another example might be number of HTTP requests to
         a particular value in a Host header.  This is an
         example of a non-host based metric since multiple
         IP addresses could respond for the same Host
         header value.

      host: :bro:type:`addr` :bro:attr:`&optional`
         Host is the value to which this metric applies.

   Represents a thing which is having summarization
   results collected for it.

.. bro:type:: SumStats::Observation

   :Type: :bro:type:`record`

      num: :bro:type:`count` :bro:attr:`&optional`
         Count value.

      dbl: :bro:type:`double` :bro:attr:`&optional`
         Double value.

      str: :bro:type:`string` :bro:attr:`&optional`
         String value.

   Represents data being added for a single observation.
   Only supply a single field at a time!

.. bro:type:: SumStats::Reducer

   :Type: :bro:type:`record`

      stream: :bro:type:`string`
         Observation stream identifier for the reducer
         to attach to.

      apply: :bro:type:`set` [:bro:type:`SumStats::Calculation`]
         The calculations to perform on the data points.

      pred: :bro:type:`function` (key: :bro:type:`SumStats::Key`, obs: :bro:type:`SumStats::Observation`) : :bro:type:`bool` :bro:attr:`&optional`
         A predicate so that you can decide per key if you
         would like to accept the data being inserted.

      normalize_key: :bro:type:`function` (key: :bro:type:`SumStats::Key`) : :bro:type:`SumStats::Key` :bro:attr:`&optional`
         A function to normalize the key.  This can be used to
         aggregate or normalize the entire key.

      ssname: :bro:type:`string` :bro:attr:`&optional`

      calc_funcs: :bro:type:`vector` of :bro:type:`SumStats::Calculation` :bro:attr:`&optional`

      hll_error_margin: :bro:type:`double` :bro:attr:`&default` = ``0.01`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)

         The error margin for HLL.

      hll_confidence: :bro:type:`double` :bro:attr:`&default` = ``0.95`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)

         The confidence for HLL.

      num_last_elements: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/last.zeek` is loaded)

         Number of elements to keep.

      num_samples: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek` is loaded)

         The number of sample Observations to collect.

      topk_size: :bro:type:`count` :bro:attr:`&default` = ``500`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/topk.zeek` is loaded)

         Number of elements to keep in the top-k list.

      unique_max: :bro:type:`count` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek` is loaded)

         Maximum number of unique values to store.

   Represents a reducer.

.. bro:type:: SumStats::Result

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`SumStats::ResultVal`

   Type to store a table of results for multiple reducers indexed by
   observation stream identifier.

.. bro:type:: SumStats::ResultTable

   :Type: :bro:type:`table` [:bro:type:`SumStats::Key`] of :bro:type:`SumStats::Result`

   Type to store a table of sumstats results indexed by keys.

.. bro:type:: SumStats::ResultVal

   :Type: :bro:type:`record`

      begin: :bro:type:`time`
         The time when the first observation was added to
         this result value.

      end: :bro:type:`time`
         The time when the last observation was added to
         this result value.

      num: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The number of observations received.

      average: :bro:type:`double` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/average.zeek` is loaded)

         For numeric data, this is the average of all values.

      hll_unique: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)

         If cardinality is being tracked, the number of unique
         items is tracked here.

      card: :bro:type:`opaque` of cardinality :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)


      hll_error_margin: :bro:type:`double` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)


      hll_confidence: :bro:type:`double` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)


      last_elements: :bro:type:`Queue::Queue` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/last.zeek` is loaded)

         This is the queue where elements are maintained.
         Don't access this value directly, instead use the
         :bro:see:`SumStats::get_last` function to get a vector of
         the current element values.

      max: :bro:type:`double` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/max.zeek` is loaded)

         For numeric data, this tracks the maximum value.

      min: :bro:type:`double` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/min.zeek` is loaded)

         For numeric data, this tracks the minimum value.

      samples: :bro:type:`vector` of :bro:type:`SumStats::Observation` :bro:attr:`&default` = ``[]`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek` is loaded)

         This is the vector in which the samples are maintained.

      sample_elements: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek` is loaded)

         Number of total observed elements.

      num_samples: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek` is loaded)


      variance: :bro:type:`double` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/variance.zeek` is loaded)

         For numeric data, this is the variance.

      prev_avg: :bro:type:`double` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/variance.zeek` is loaded)


      var_s: :bro:type:`double` :bro:attr:`&default` = ``0.0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/variance.zeek` is loaded)


      std_dev: :bro:type:`double` :bro:attr:`&default` = ``0.0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/std-dev.zeek` is loaded)

         For numeric data, this calculates the standard deviation.

      sum: :bro:type:`double` :bro:attr:`&default` = ``0.0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sum.zeek` is loaded)

         For numeric data, this tracks the sum of all values.

      topk: :bro:type:`opaque` of topk :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/topk.zeek` is loaded)

         A handle which can be passed to some built-in functions to get
         the top-k results.

      unique: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek` is loaded)

         If cardinality is being tracked, the number of unique
         values is tracked here.

      unique_max: :bro:type:`count` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek` is loaded)


      unique_vals: :bro:type:`set` [:bro:type:`SumStats::Observation`] :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek` is loaded)


   Result calculated for an observation stream fed into a reducer.
   Most of the fields are added by plugins.

.. bro:type:: SumStats::SumStat

   :Type: :bro:type:`record`

      name: :bro:type:`string`
         An arbitrary name for the sumstat so that it can 
         be referred to later.

      epoch: :bro:type:`interval`
         The interval at which this filter should be "broken"
         and the *epoch_result* callback called.  The
         results are also reset at this time so any threshold
         based detection needs to be set to a
         value that should be expected to happen within
         this epoch.

      reducers: :bro:type:`set` [:bro:type:`SumStats::Reducer`]
         The reducers for the SumStat.

      threshold_val: :bro:type:`function` (key: :bro:type:`SumStats::Key`, result: :bro:type:`SumStats::Result`) : :bro:type:`double` :bro:attr:`&optional`
         A function that will be called once for each observation in order
         to calculate a value from the :bro:see:`SumStats::Result` structure
         which will be used for thresholding.
         This function is required if a *threshold* value or
         a *threshold_series* is given.

      threshold: :bro:type:`double` :bro:attr:`&optional`
         The threshold value for calling the *threshold_crossed* callback.
         If you need more than one threshold value, then use
         *threshold_series* instead.

      threshold_series: :bro:type:`vector` of :bro:type:`double` :bro:attr:`&optional`
         A series of thresholds for calling the *threshold_crossed*
         callback.  These thresholds must be listed in ascending order,
         because a threshold is not checked until the preceding one has
         been crossed.

      threshold_crossed: :bro:type:`function` (key: :bro:type:`SumStats::Key`, result: :bro:type:`SumStats::Result`) : :bro:type:`void` :bro:attr:`&optional`
         A callback that is called when a threshold is crossed.
         A threshold is crossed when the value returned from *threshold_val*
         is greater than or equal to the threshold value, but only the first
         time this happens within an epoch.

      epoch_result: :bro:type:`function` (ts: :bro:type:`time`, key: :bro:type:`SumStats::Key`, result: :bro:type:`SumStats::Result`) : :bro:type:`void` :bro:attr:`&optional`
         A callback that receives each of the results at the
         end of the analysis epoch.  The function will be 
         called once for each key.

      epoch_finished: :bro:type:`function` (ts: :bro:type:`time`) : :bro:type:`void` :bro:attr:`&optional`
         A callback that will be called when a single collection 
         interval is completed.  The *ts* value will be the time of 
         when the collection started.

   Represents a SumStat, which consists of an aggregation of reducers along
   with mechanisms to handle various situations like the epoch ending
   or thresholds being crossed.
   
   It's best to not access any global state outside
   of the variables given to the callbacks because there
   is no assurance provided as to where the callbacks
   will be executed on clusters.

Functions
#########
.. bro:id:: SumStats::create

   :Type: :bro:type:`function` (ss: :bro:type:`SumStats::SumStat`) : :bro:type:`void`

   Create a summary statistic.
   

   :ss: The SumStat to create.

.. bro:id:: SumStats::key2str

   :Type: :bro:type:`function` (key: :bro:type:`SumStats::Key`) : :bro:type:`string`

   Helper function to represent a :bro:type:`SumStats::Key` value as
   a simple string.
   

   :key: The metric key that is to be converted into a string.
   

   :returns: A string representation of the metric key.

.. bro:id:: SumStats::observe

   :Type: :bro:type:`function` (id: :bro:type:`string`, orig_key: :bro:type:`SumStats::Key`, obs: :bro:type:`SumStats::Observation`) : :bro:type:`void`

   Add data into an observation stream. This should be
   called when a script has measured some point value.
   

   :id: The observation stream identifier that the data
       point represents.
   

   :key: The key that the value is related to.
   

   :obs: The data point to send into the stream.

.. bro:id:: SumStats::request_key

   :Type: :bro:type:`function` (ss_name: :bro:type:`string`, key: :bro:type:`SumStats::Key`) : :bro:type:`SumStats::Result`

   Dynamically request a sumstat key.  This function should be
   used sparingly and not as a replacement for the callbacks 
   from the :bro:see:`SumStats::SumStat` record.  The function is only
   available for use within "when" statements as an asynchronous
   function.
   

   :ss_name: SumStat name.
   

   :key: The SumStat key being requested.
   

   :returns: The result for the requested sumstat key.


