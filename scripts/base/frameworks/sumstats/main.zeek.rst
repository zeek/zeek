:tocdepth: 3

base/frameworks/sumstats/main.zeek
==================================
.. zeek:namespace:: SumStats

The summary statistics framework provides a way to
summarize large streams of data into simple reduced
measurements.

:Namespace: SumStats

Summary
~~~~~~~
Types
#####
======================================================= ========================================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum`   Type to represent the calculations that are available.
:zeek:type:`SumStats::Key`: :zeek:type:`record`         Represents a thing which is having summarization
                                                        results collected for it.
:zeek:type:`SumStats::Observation`: :zeek:type:`record` Represents data being added for a single observation.
:zeek:type:`SumStats::Reducer`: :zeek:type:`record`     Represents a reducer.
:zeek:type:`SumStats::Result`: :zeek:type:`table`       Type to store a table of results for multiple reducers indexed by
                                                        observation stream identifier.
:zeek:type:`SumStats::ResultTable`: :zeek:type:`table`  Type to store a table of sumstats results indexed by keys.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record`   Result calculated for an observation stream fed into a reducer.
:zeek:type:`SumStats::SumStat`: :zeek:type:`record`     Represents a SumStat, which consists of an aggregation of reducers along
                                                        with mechanisms to handle various situations like the epoch ending
                                                        or thresholds being crossed.
======================================================= ========================================================================

Redefinitions
#############
=================================================== =
:zeek:type:`SumStats::Reducer`: :zeek:type:`record` 
=================================================== =

Functions
#########
======================================================= ==================================================================
:zeek:id:`SumStats::create`: :zeek:type:`function`      Create a summary statistic.
:zeek:id:`SumStats::key2str`: :zeek:type:`function`     Helper function to represent a :zeek:type:`SumStats::Key` value as
                                                        a simple string.
:zeek:id:`SumStats::observe`: :zeek:type:`function`     Add data into an observation stream.
:zeek:id:`SumStats::request_key`: :zeek:type:`function` Dynamically request a sumstat key.
======================================================= ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: SumStats::Calculation

   :Type: :zeek:type:`enum`

      .. zeek:enum:: SumStats::PLACEHOLDER SumStats::Calculation

      .. zeek:enum:: SumStats::AVERAGE SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/average.zeek` is loaded)


         Calculate the average of the values.

      .. zeek:enum:: SumStats::HLL_UNIQUE SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)


         Calculate the number of unique values.

      .. zeek:enum:: SumStats::LAST SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/last.zeek` is loaded)


         Keep last X observations in a queue.

      .. zeek:enum:: SumStats::MAX SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/max.zeek` is loaded)


         Find the maximum value.

      .. zeek:enum:: SumStats::MIN SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/min.zeek` is loaded)


         Find the minimum value.

      .. zeek:enum:: SumStats::SAMPLE SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek` is loaded)


         Get uniquely distributed random samples from the observation
         stream.

      .. zeek:enum:: SumStats::VARIANCE SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/variance.zeek` is loaded)


         Calculate the variance of the values.

      .. zeek:enum:: SumStats::STD_DEV SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/std-dev.zeek` is loaded)


         Calculate the standard deviation of the values.

      .. zeek:enum:: SumStats::SUM SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sum.zeek` is loaded)


         Calculate the sum of the values.  For string values,
         this will be the number of strings.

      .. zeek:enum:: SumStats::TOPK SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/topk.zeek` is loaded)


         Keep a top-k list of values.

      .. zeek:enum:: SumStats::UNIQUE SumStats::Calculation

         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek` is loaded)


         Calculate the number of unique values.

   Type to represent the calculations that are available.  The calculations
   are all defined as plugins.

.. zeek:type:: SumStats::Key

   :Type: :zeek:type:`record`

      str: :zeek:type:`string` :zeek:attr:`&optional`
         A non-address related summarization or a sub-key for
         an address based summarization. An example might be
         successful SSH connections by client IP address
         where the client string would be the key value.
         Another example might be number of HTTP requests to
         a particular value in a Host header.  This is an
         example of a non-host based metric since multiple
         IP addresses could respond for the same Host
         header value.

      host: :zeek:type:`addr` :zeek:attr:`&optional`
         Host is the value to which this metric applies.

   Represents a thing which is having summarization
   results collected for it.

.. zeek:type:: SumStats::Observation

   :Type: :zeek:type:`record`

      num: :zeek:type:`count` :zeek:attr:`&optional`
         Count value.

      dbl: :zeek:type:`double` :zeek:attr:`&optional`
         Double value.

      str: :zeek:type:`string` :zeek:attr:`&optional`
         String value.

   Represents data being added for a single observation.
   Only supply a single field at a time!

.. zeek:type:: SumStats::Reducer

   :Type: :zeek:type:`record`

      stream: :zeek:type:`string`
         Observation stream identifier for the reducer
         to attach to.

      apply: :zeek:type:`set` [:zeek:type:`SumStats::Calculation`]
         The calculations to perform on the data points.

      pred: :zeek:type:`function` (key: :zeek:type:`SumStats::Key`, obs: :zeek:type:`SumStats::Observation`) : :zeek:type:`bool` :zeek:attr:`&optional`
         A predicate so that you can decide per key if you
         would like to accept the data being inserted.

      normalize_key: :zeek:type:`function` (key: :zeek:type:`SumStats::Key`) : :zeek:type:`SumStats::Key` :zeek:attr:`&optional`
         A function to normalize the key.  This can be used to
         aggregate or normalize the entire key.

      ssname: :zeek:type:`string` :zeek:attr:`&optional`

      calc_funcs: :zeek:type:`vector` of :zeek:type:`SumStats::Calculation` :zeek:attr:`&optional`

      hll_error_margin: :zeek:type:`double` :zeek:attr:`&default` = ``0.01`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)

         The error margin for HLL.

      hll_confidence: :zeek:type:`double` :zeek:attr:`&default` = ``0.95`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)

         The confidence for HLL.

      num_last_elements: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/last.zeek` is loaded)

         Number of elements to keep.

      num_samples: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek` is loaded)

         The number of sample Observations to collect.

      topk_size: :zeek:type:`count` :zeek:attr:`&default` = ``500`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/topk.zeek` is loaded)

         Number of elements to keep in the top-k list.

      unique_max: :zeek:type:`count` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek` is loaded)

         Maximum number of unique values to store.

   Represents a reducer.

.. zeek:type:: SumStats::Result

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`SumStats::ResultVal`

   Type to store a table of results for multiple reducers indexed by
   observation stream identifier.

.. zeek:type:: SumStats::ResultTable

   :Type: :zeek:type:`table` [:zeek:type:`SumStats::Key`] of :zeek:type:`SumStats::Result`

   Type to store a table of sumstats results indexed by keys.

.. zeek:type:: SumStats::ResultVal

   :Type: :zeek:type:`record`

      begin: :zeek:type:`time`
         The time when the first observation was added to
         this result value.

      end: :zeek:type:`time`
         The time when the last observation was added to
         this result value.

      num: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The number of observations received.

      average: :zeek:type:`double` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/average.zeek` is loaded)

         For numeric data, this is the average of all values.

      hll_unique: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)

         If cardinality is being tracked, the number of unique
         items is tracked here.

      card: :zeek:type:`opaque` of cardinality :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)


      hll_error_margin: :zeek:type:`double` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)


      hll_confidence: :zeek:type:`double` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/hll_unique.zeek` is loaded)


      last_elements: :zeek:type:`Queue::Queue` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/last.zeek` is loaded)

         This is the queue where elements are maintained.
         Don't access this value directly, instead use the
         :zeek:see:`SumStats::get_last` function to get a vector of
         the current element values.

      max: :zeek:type:`double` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/max.zeek` is loaded)

         For numeric data, this tracks the maximum value.

      min: :zeek:type:`double` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/min.zeek` is loaded)

         For numeric data, this tracks the minimum value.

      samples: :zeek:type:`vector` of :zeek:type:`SumStats::Observation` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek` is loaded)

         This is the vector in which the samples are maintained.

      sample_elements: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek` is loaded)

         Number of total observed elements.

      num_samples: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sample.zeek` is loaded)


      variance: :zeek:type:`double` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/variance.zeek` is loaded)

         For numeric data, this is the variance.

      prev_avg: :zeek:type:`double` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/variance.zeek` is loaded)


      var_s: :zeek:type:`double` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/variance.zeek` is loaded)


      std_dev: :zeek:type:`double` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/std-dev.zeek` is loaded)

         For numeric data, this calculates the standard deviation.

      sum: :zeek:type:`double` :zeek:attr:`&default` = ``0.0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/sum.zeek` is loaded)

         For numeric data, this tracks the sum of all values.

      topk: :zeek:type:`opaque` of topk :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/topk.zeek` is loaded)

         A handle which can be passed to some built-in functions to get
         the top-k results.

      unique: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek` is loaded)

         If cardinality is being tracked, the number of unique
         values is tracked here.

      unique_max: :zeek:type:`count` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek` is loaded)


      unique_vals: :zeek:type:`set` [:zeek:type:`SumStats::Observation`] :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/sumstats/plugins/unique.zeek` is loaded)


   Result calculated for an observation stream fed into a reducer.
   Most of the fields are added by plugins.

.. zeek:type:: SumStats::SumStat

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         An arbitrary name for the sumstat so that it can 
         be referred to later.

      epoch: :zeek:type:`interval`
         The interval at which this filter should be "broken"
         and the *epoch_result* callback called.  The
         results are also reset at this time so any threshold
         based detection needs to be set to a
         value that should be expected to happen within
         this epoch.

      reducers: :zeek:type:`set` [:zeek:type:`SumStats::Reducer`]
         The reducers for the SumStat.

      threshold_val: :zeek:type:`function` (key: :zeek:type:`SumStats::Key`, result: :zeek:type:`SumStats::Result`) : :zeek:type:`double` :zeek:attr:`&optional`
         A function that will be called once for each observation in order
         to calculate a value from the :zeek:see:`SumStats::Result` structure
         which will be used for thresholding.
         This function is required if a *threshold* value or
         a *threshold_series* is given.

      threshold: :zeek:type:`double` :zeek:attr:`&optional`
         The threshold value for calling the *threshold_crossed* callback.
         If you need more than one threshold value, then use
         *threshold_series* instead.

      threshold_series: :zeek:type:`vector` of :zeek:type:`double` :zeek:attr:`&optional`
         A series of thresholds for calling the *threshold_crossed*
         callback.  These thresholds must be listed in ascending order,
         because a threshold is not checked until the preceding one has
         been crossed.

      threshold_crossed: :zeek:type:`function` (key: :zeek:type:`SumStats::Key`, result: :zeek:type:`SumStats::Result`) : :zeek:type:`void` :zeek:attr:`&optional`
         A callback that is called when a threshold is crossed.
         A threshold is crossed when the value returned from *threshold_val*
         is greater than or equal to the threshold value, but only the first
         time this happens within an epoch.

      epoch_result: :zeek:type:`function` (ts: :zeek:type:`time`, key: :zeek:type:`SumStats::Key`, result: :zeek:type:`SumStats::Result`) : :zeek:type:`void` :zeek:attr:`&optional`
         A callback that receives each of the results at the
         end of the analysis epoch.  The function will be 
         called once for each key.

      epoch_finished: :zeek:type:`function` (ts: :zeek:type:`time`) : :zeek:type:`void` :zeek:attr:`&optional`
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
.. zeek:id:: SumStats::create

   :Type: :zeek:type:`function` (ss: :zeek:type:`SumStats::SumStat`) : :zeek:type:`void`

   Create a summary statistic.
   

   :ss: The SumStat to create.

.. zeek:id:: SumStats::key2str

   :Type: :zeek:type:`function` (key: :zeek:type:`SumStats::Key`) : :zeek:type:`string`

   Helper function to represent a :zeek:type:`SumStats::Key` value as
   a simple string.
   

   :key: The metric key that is to be converted into a string.
   

   :returns: A string representation of the metric key.

.. zeek:id:: SumStats::observe

   :Type: :zeek:type:`function` (id: :zeek:type:`string`, orig_key: :zeek:type:`SumStats::Key`, obs: :zeek:type:`SumStats::Observation`) : :zeek:type:`void`

   Add data into an observation stream. This should be
   called when a script has measured some point value.
   

   :id: The observation stream identifier that the data
       point represents.
   

   :key: The key that the value is related to.
   

   :obs: The data point to send into the stream.

.. zeek:id:: SumStats::request_key

   :Type: :zeek:type:`function` (ss_name: :zeek:type:`string`, key: :zeek:type:`SumStats::Key`) : :zeek:type:`SumStats::Result`

   Dynamically request a sumstat key.  This function should be
   used sparingly and not as a replacement for the callbacks 
   from the :zeek:see:`SumStats::SumStat` record.  The function is only
   available for use within "when" statements as an asynchronous
   function.
   

   :ss_name: SumStat name.
   

   :key: The SumStat key being requested.
   

   :returns: The result for the requested sumstat key.


