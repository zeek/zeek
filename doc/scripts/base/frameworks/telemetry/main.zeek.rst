:tocdepth: 3

base/frameworks/telemetry/main.zeek
===================================
.. zeek:namespace:: Telemetry

Module for recording and querying metrics. This modules wraps
the lower-level telemetry.bif functions.

Metrics will be exposed through a Prometheus HTTP endpoint when
enabled by setting :zeek:see:`Telemetry::metrics_port`.

:Namespace: Telemetry
:Imports: :doc:`base/bif/telemetry_functions.bif.zeek </scripts/base/bif/telemetry_functions.bif.zeek>`, :doc:`base/misc/version.zeek </scripts/base/misc/version.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=============================================================================================================== ==================================================================
:zeek:id:`Telemetry::sync_interval`: :zeek:type:`interval` :zeek:attr:`&deprecated` = *...* :zeek:attr:`&redef` Interval at which the :zeek:see:`Telemetry::sync` hook is invoked.
=============================================================================================================== ==================================================================

Types
#####
============================================================ =========================================================================
:zeek:type:`Telemetry::Counter`: :zeek:type:`record`         Type representing a counter metric with initialized label values.
:zeek:type:`Telemetry::CounterFamily`: :zeek:type:`record`   Type representing a family of counters with uninitialized label values.
:zeek:type:`Telemetry::Gauge`: :zeek:type:`record`           Type representing a gauge metric with initialized label values.
:zeek:type:`Telemetry::GaugeFamily`: :zeek:type:`record`     Type representing a family of gauges with uninitialized label values.
:zeek:type:`Telemetry::Histogram`: :zeek:type:`record`       Type representing a histogram metric with initialized label values.
:zeek:type:`Telemetry::HistogramFamily`: :zeek:type:`record` Type representing a family of histograms with uninitialized label values.
:zeek:type:`Telemetry::labels_vector`: :zeek:type:`vector`   Alias for a vector of label values.
============================================================ =========================================================================

Functions
#########
====================================================================== ============================================================================================
:zeek:id:`Telemetry::collect_histogram_metrics`: :zeek:type:`function` Collect all histograms and their observations matching the given
                                                                       *prefix* and *name*.
:zeek:id:`Telemetry::collect_metrics`: :zeek:type:`function`           Collect all counter and gauge metrics matching the given *name* and *prefix*.
:zeek:id:`Telemetry::counter_family_inc`: :zeek:type:`function`        Increment a :zeek:see:`Telemetry::Counter` through the :zeek:see:`Telemetry::CounterFamily`.
:zeek:id:`Telemetry::counter_family_set`: :zeek:type:`function`        Set a :zeek:see:`Telemetry::Counter` through the :zeek:see:`Telemetry::CounterFamily`.
:zeek:id:`Telemetry::counter_inc`: :zeek:type:`function`               Increment a :zeek:see:`Telemetry::Counter` by ``amount``.
:zeek:id:`Telemetry::counter_set`: :zeek:type:`function`               Helper to set a :zeek:see:`Telemetry::Counter` to the given ``value``.
:zeek:id:`Telemetry::counter_with`: :zeek:type:`function`              Get a :zeek:see:`Telemetry::Counter` instance given family and label values.
:zeek:id:`Telemetry::gauge_dec`: :zeek:type:`function`                 Decrement a :zeek:see:`Telemetry::Gauge` by ``amount``.
:zeek:id:`Telemetry::gauge_family_dec`: :zeek:type:`function`          Decrement a :zeek:see:`Telemetry::Gauge` by the given ``amount`` through
                                                                       the :zeek:see:`Telemetry::GaugeFamily`.
:zeek:id:`Telemetry::gauge_family_inc`: :zeek:type:`function`          Increment a :zeek:see:`Telemetry::Gauge` by the given ``amount`` through
                                                                       the :zeek:see:`Telemetry::GaugeFamily`.
:zeek:id:`Telemetry::gauge_family_set`: :zeek:type:`function`          Set a :zeek:see:`Telemetry::Gauge` to the given ``value`` through
                                                                       the :zeek:see:`Telemetry::GaugeFamily`.
:zeek:id:`Telemetry::gauge_inc`: :zeek:type:`function`                 Increment a :zeek:see:`Telemetry::Gauge` by ``amount``.
:zeek:id:`Telemetry::gauge_set`: :zeek:type:`function`                 Helper to set a :zeek:see:`Telemetry::Gauge` to the given ``value``.
:zeek:id:`Telemetry::gauge_with`: :zeek:type:`function`                Get a :zeek:see:`Telemetry::Gauge` instance given family and label values.
:zeek:id:`Telemetry::histogram_family_observe`: :zeek:type:`function`  Observe a measurement for a :zeek:see:`Telemetry::Histogram` through
                                                                       the :zeek:see:`Telemetry::HistogramFamily`.
:zeek:id:`Telemetry::histogram_observe`: :zeek:type:`function`         Observe a measurement for a :zeek:see:`Telemetry::Histogram`.
:zeek:id:`Telemetry::histogram_with`: :zeek:type:`function`            Get a :zeek:see:`Telemetry::Histogram` instance given family and label values.
:zeek:id:`Telemetry::register_counter_family`: :zeek:type:`function`   Register a counter family.
:zeek:id:`Telemetry::register_gauge_family`: :zeek:type:`function`     Register a gauge family.
:zeek:id:`Telemetry::register_histogram_family`: :zeek:type:`function` Register a histogram family.
====================================================================== ============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Telemetry::sync_interval
   :source-code: base/frameworks/telemetry/main.zeek 256 256

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in 8.1. If you require regular sync invocation, do so explicitly in a scheduled event."* :zeek:attr:`&redef`
   :Default: ``0 secs``

   Interval at which the :zeek:see:`Telemetry::sync` hook is invoked.
   
   By default, the hook is invoked on demand, setting this option to
   a positive interval allows to invoke it regularly, too. Regular
   invocations are relative to Zeek's network time.
   
   Note that on-demand hook invocation will happen even if this
   is set.

Types
#####
.. zeek:type:: Telemetry::Counter
   :source-code: base/frameworks/telemetry/main.zeek 34 36

   :Type: :zeek:type:`record`


   .. zeek:field:: __metric :zeek:type:`opaque` of counter_metric


   Type representing a counter metric with initialized label values.
   
   Counter metrics only ever go up and reset when the process
   restarts. Use :zeek:see:`Telemetry::counter_inc` or
   :zeek:see:`Telemetry::counter_set` to modify counters.
   An example for a counter is the number of log writes
   per :zeek:see:`Log::Stream` or number connections broken down
   by protocol and service.

.. zeek:type:: Telemetry::CounterFamily
   :source-code: base/frameworks/telemetry/main.zeek 21 24

   :Type: :zeek:type:`record`


   .. zeek:field:: __family :zeek:type:`opaque` of counter_metric_family


   .. zeek:field:: __labels :zeek:type:`vector` of :zeek:type:`string`


   Type representing a family of counters with uninitialized label values.
   
   To create concrete :zeek:see:`Telemetry::Counter` instances, use
   :zeek:see:`Telemetry::counter_with`. To modify counters directly
   use :zeek:see:`Telemetry::counter_family_inc`.

.. zeek:type:: Telemetry::Gauge
   :source-code: base/frameworks/telemetry/main.zeek 117 119

   :Type: :zeek:type:`record`


   .. zeek:field:: __metric :zeek:type:`opaque` of gauge_metric


   Type representing a gauge metric with initialized label values.
   
   Use :zeek:see:`Telemetry::gauge_inc`, :zeek:see:`Telemetry::gauge_dec`,
   or :zeek:see:`Telemetry::gauge_set` to modify the gauge.
   Example for gauges are process memory usage, table sizes
   or footprints of long-lived values as determined by
   :zeek:see:`val_footprint`.

.. zeek:type:: Telemetry::GaugeFamily
   :source-code: base/frameworks/telemetry/main.zeek 105 108

   :Type: :zeek:type:`record`


   .. zeek:field:: __family :zeek:type:`opaque` of gauge_metric_family


   .. zeek:field:: __labels :zeek:type:`vector` of :zeek:type:`string`


   Type representing a family of gauges with uninitialized label values.
   
   Create concrete :zeek:see:`Telemetry::Gauge` instances with
   :zeek:see:`Telemetry::gauge_with`, or use
   :zeek:see:`Telemetry::gauge_family_inc` or
   :zeek:see:`Telemetry::gauge_family_set` directly.

.. zeek:type:: Telemetry::Histogram
   :source-code: base/frameworks/telemetry/main.zeek 213 215

   :Type: :zeek:type:`record`


   .. zeek:field:: __metric :zeek:type:`opaque` of histogram_metric


   Type representing a histogram metric with initialized label values.
   Use :zeek:see:`Telemetry::histogram_observe` to make observations.

.. zeek:type:: Telemetry::HistogramFamily
   :source-code: base/frameworks/telemetry/main.zeek 206 209

   :Type: :zeek:type:`record`


   .. zeek:field:: __family :zeek:type:`opaque` of histogram_metric_family


   .. zeek:field:: __labels :zeek:type:`vector` of :zeek:type:`string`


   Type representing a family of histograms with uninitialized label values.
   Create concrete :zeek:see:`Telemetry::Histogram` instances with
   :zeek:see:`Telemetry::histogram_with` or use
   :zeek:see:`Telemetry::histogram_family_observe` directly.

.. zeek:type:: Telemetry::labels_vector
   :source-code: base/frameworks/telemetry/main.zeek 14 14

   :Type: :zeek:type:`vector` of :zeek:type:`string`

   Alias for a vector of label values.

Functions
#########
.. zeek:id:: Telemetry::collect_histogram_metrics
   :source-code: base/frameworks/telemetry/main.zeek 463 466

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string` :zeek:attr:`&default` = ``"*"`` :zeek:attr:`&optional`, name: :zeek:type:`string` :zeek:attr:`&default` = ``"*"`` :zeek:attr:`&optional`) : :zeek:type:`vector` of :zeek:type:`Telemetry::HistogramMetric`

   Collect all histograms and their observations matching the given
   *prefix* and *name*.
   
   The *prefix* and *name* parameters support globbing. By default,
   all histogram metrics are returned.

.. zeek:id:: Telemetry::collect_metrics
   :source-code: base/frameworks/telemetry/main.zeek 458 461

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string` :zeek:attr:`&default` = ``"*"`` :zeek:attr:`&optional`, name: :zeek:type:`string` :zeek:attr:`&default` = ``"*"`` :zeek:attr:`&optional`) : :zeek:type:`vector` of :zeek:type:`Telemetry::Metric`

   Collect all counter and gauge metrics matching the given *name* and *prefix*.
   
   For histogram metrics, use the :zeek:see:`Telemetry::collect_histogram_metrics`.
   
   The *prefix* and *name* parameters support globbing. By default,
   all counters and gauges are returned.

.. zeek:id:: Telemetry::counter_family_inc
   :source-code: base/frameworks/telemetry/main.zeek 335 338

   :Type: :zeek:type:`function` (cf: :zeek:type:`Telemetry::CounterFamily`, label_values: :zeek:type:`Telemetry::labels_vector` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`, amount: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Increment a :zeek:see:`Telemetry::Counter` through the :zeek:see:`Telemetry::CounterFamily`.
   This is a short-cut for :zeek:see:`Telemetry::counter_inc`.
   Using a negative amount is an error.
   

   :param cf: The counter family to use.
   

   :param label_values: The label values to use for the counter.
   

   :param amount: The amount by which to increment the counter.
   

   :returns: True if the counter was incremented successfully.

.. zeek:id:: Telemetry::counter_family_set
   :source-code: base/frameworks/telemetry/main.zeek 340 343

   :Type: :zeek:type:`function` (cf: :zeek:type:`Telemetry::CounterFamily`, label_values: :zeek:type:`Telemetry::labels_vector`, value: :zeek:type:`double`) : :zeek:type:`bool`

   Set a :zeek:see:`Telemetry::Counter` through the :zeek:see:`Telemetry::CounterFamily`.
   This is a short-cut for :zeek:see:`Telemetry::counter_set`.
   Setting a value that is less than the current value of the
   metric is an error and will be ignored.
   

   :param cf: The counter family to use.
   

   :param label_values: The label values to use for the counter.
   

   :param value: The value to set the counter to.
   

   :returns: True if the counter value was set successfully.

.. zeek:id:: Telemetry::counter_inc
   :source-code: base/frameworks/telemetry/main.zeek 319 322

   :Type: :zeek:type:`function` (c: :zeek:type:`Telemetry::Counter`, amount: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Increment a :zeek:see:`Telemetry::Counter` by ``amount``.
   Using a negative ``amount`` is an error.
   

   :param c: The counter instance.
   

   :param amount: The amount by which to increment the counter.
   

   :returns: True if the counter was incremented successfully.

.. zeek:id:: Telemetry::counter_set
   :source-code: base/frameworks/telemetry/main.zeek 324 333

   :Type: :zeek:type:`function` (c: :zeek:type:`Telemetry::Counter`, value: :zeek:type:`double`) : :zeek:type:`bool`

   Helper to set a :zeek:see:`Telemetry::Counter` to the given ``value``.
   This can be useful for mirroring counter metrics in an
   :zeek:see:`Telemetry::sync` hook implementation.
   Setting a value that is less than the current value of the
   metric is an error and will be ignored.
   

   :param c: The counter instance.
   

   :param value: The value to set the counter to.
   

   :returns: True if the counter value was set successfully.

.. zeek:id:: Telemetry::counter_with
   :source-code: base/frameworks/telemetry/main.zeek 306 317

   :Type: :zeek:type:`function` (cf: :zeek:type:`Telemetry::CounterFamily`, label_values: :zeek:type:`Telemetry::labels_vector` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`) : :zeek:type:`Telemetry::Counter`

   Get a :zeek:see:`Telemetry::Counter` instance given family and label values.

.. zeek:id:: Telemetry::gauge_dec
   :source-code: base/frameworks/telemetry/main.zeek 382 385

   :Type: :zeek:type:`function` (g: :zeek:type:`Telemetry::Gauge`, amount: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Decrement a :zeek:see:`Telemetry::Gauge` by ``amount``.
   

   :param g: The gauge instance.
   

   :param amount: The amount by which to decrement the gauge.
   

   :returns: True if the gauge was incremented successfully.

.. zeek:id:: Telemetry::gauge_family_dec
   :source-code: base/frameworks/telemetry/main.zeek 403 406

   :Type: :zeek:type:`function` (gf: :zeek:type:`Telemetry::GaugeFamily`, label_values: :zeek:type:`Telemetry::labels_vector` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`, value: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Decrement a :zeek:see:`Telemetry::Gauge` by the given ``amount`` through
   the :zeek:see:`Telemetry::GaugeFamily`.
   This is a short-cut for :zeek:see:`Telemetry::gauge_dec`.
   

   :param gf: The gauge family to use.
   

   :param label_values: The label values to use for the gauge.
   

   :param amount: The amount by which to increment the gauge.
   

   :returns: True if the gauge was incremented successfully.

.. zeek:id:: Telemetry::gauge_family_inc
   :source-code: base/frameworks/telemetry/main.zeek 398 401

   :Type: :zeek:type:`function` (gf: :zeek:type:`Telemetry::GaugeFamily`, label_values: :zeek:type:`Telemetry::labels_vector` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`, value: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Increment a :zeek:see:`Telemetry::Gauge` by the given ``amount`` through
   the :zeek:see:`Telemetry::GaugeFamily`.
   This is a short-cut for :zeek:see:`Telemetry::gauge_inc`.
   Using a negative amount is an error.
   

   :param gf: The gauge family to use.
   

   :param label_values: The label values to use for the gauge.
   

   :param amount: The amount by which to increment the gauge.
   

   :returns: True if the gauge was incremented successfully.

.. zeek:id:: Telemetry::gauge_family_set
   :source-code: base/frameworks/telemetry/main.zeek 408 411

   :Type: :zeek:type:`function` (gf: :zeek:type:`Telemetry::GaugeFamily`, label_values: :zeek:type:`Telemetry::labels_vector`, value: :zeek:type:`double`) : :zeek:type:`bool`

   Set a :zeek:see:`Telemetry::Gauge` to the given ``value`` through
   the :zeek:see:`Telemetry::GaugeFamily`.
   This is a short-cut for :zeek:see:`Telemetry::gauge_set`.
   

   :param gf: The gauge family to use.
   

   :param label_values: The label values to use for the gauge.
   

   :param value: The value to set the gauge to.
   

   :returns: True if the gauge value was set successfully.

.. zeek:id:: Telemetry::gauge_inc
   :source-code: base/frameworks/telemetry/main.zeek 377 380

   :Type: :zeek:type:`function` (g: :zeek:type:`Telemetry::Gauge`, amount: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Increment a :zeek:see:`Telemetry::Gauge` by ``amount``.
   

   :param g: The gauge instance.
   

   :param amount: The amount by which to increment the gauge.
   

   :returns: True if the gauge was incremented successfully.

.. zeek:id:: Telemetry::gauge_set
   :source-code: base/frameworks/telemetry/main.zeek 387 396

   :Type: :zeek:type:`function` (g: :zeek:type:`Telemetry::Gauge`, value: :zeek:type:`double`) : :zeek:type:`bool`

   Helper to set a :zeek:see:`Telemetry::Gauge` to the given ``value``.
   

   :param g: The gauge instance.
   

   :param value: The value to set the gauge to.
   

   :returns: True if the gauge value was set successfully.

.. zeek:id:: Telemetry::gauge_with
   :source-code: base/frameworks/telemetry/main.zeek 365 375

   :Type: :zeek:type:`function` (gf: :zeek:type:`Telemetry::GaugeFamily`, label_values: :zeek:type:`Telemetry::labels_vector` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`) : :zeek:type:`Telemetry::Gauge`

   Get a :zeek:see:`Telemetry::Gauge` instance given family and label values.

.. zeek:id:: Telemetry::histogram_family_observe
   :source-code: base/frameworks/telemetry/main.zeek 453 456

   :Type: :zeek:type:`function` (hf: :zeek:type:`Telemetry::HistogramFamily`, label_values: :zeek:type:`Telemetry::labels_vector`, measurement: :zeek:type:`double`) : :zeek:type:`bool`

   Observe a measurement for a :zeek:see:`Telemetry::Histogram` through
   the :zeek:see:`Telemetry::HistogramFamily`.
   This is a short-cut for :zeek:see:`Telemetry::histogram_observe`.
   

   :param hf: The histogram family to use.
   

   :param label_values: The label values to use for the histogram.
   

   :param measurement: The value for this observations.
   

   :returns: True if measurement was observed successfully.

.. zeek:id:: Telemetry::histogram_observe
   :source-code: base/frameworks/telemetry/main.zeek 448 451

   :Type: :zeek:type:`function` (h: :zeek:type:`Telemetry::Histogram`, measurement: :zeek:type:`double`) : :zeek:type:`bool`

   Observe a measurement for a :zeek:see:`Telemetry::Histogram`.
   

   :param h: The histogram instance.
   

   :param measurement: The value for this observations.
   

   :returns: True if measurement was observed successfully.

.. zeek:id:: Telemetry::histogram_with
   :source-code: base/frameworks/telemetry/main.zeek 435 446

   :Type: :zeek:type:`function` (hf: :zeek:type:`Telemetry::HistogramFamily`, label_values: :zeek:type:`Telemetry::labels_vector` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`) : :zeek:type:`Telemetry::Histogram`

   Get a :zeek:see:`Telemetry::Histogram` instance given family and label values.

.. zeek:id:: Telemetry::register_counter_family
   :source-code: base/frameworks/telemetry/main.zeek 286 296

   :Type: :zeek:type:`function` (opts: :zeek:type:`Telemetry::MetricOpts`) : :zeek:type:`Telemetry::CounterFamily`

   Register a counter family.

.. zeek:id:: Telemetry::register_gauge_family
   :source-code: base/frameworks/telemetry/main.zeek 345 355

   :Type: :zeek:type:`function` (opts: :zeek:type:`Telemetry::MetricOpts`) : :zeek:type:`Telemetry::GaugeFamily`

   Register a gauge family.

.. zeek:id:: Telemetry::register_histogram_family
   :source-code: base/frameworks/telemetry/main.zeek 413 424

   :Type: :zeek:type:`function` (opts: :zeek:type:`Telemetry::MetricOpts`) : :zeek:type:`Telemetry::HistogramFamily`

   Register a histogram family.


