:tocdepth: 3

policy/frameworks/telemetry/log.zeek
====================================
.. zeek:namespace:: Telemetry

Implementation of a :file:`telemetry.log` and :file:`telemetry_histogram.log`
file using metrics accessible via the Telemetry module.

:Namespace: Telemetry
:Imports: :doc:`base/frameworks/telemetry </scripts/base/frameworks/telemetry/index>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================= ===============================================================
:zeek:id:`Telemetry::log_interval`: :zeek:type:`interval` :zeek:attr:`&redef` How often metrics are reported.
:zeek:id:`Telemetry::log_prefixes`: :zeek:type:`set` :zeek:attr:`&redef`      Only metrics with prefixes in this set will be included in the
                                                                              :file:`telemetry.log` and :file:`telemetry_histogram.log` files
                                                                              by default.
============================================================================= ===============================================================

Types
#####
========================================================== =======================================================
:zeek:type:`Telemetry::HistogramInfo`: :zeek:type:`record` Record type used for logging histogram metrics.
:zeek:type:`Telemetry::Info`: :zeek:type:`record`          Record type used for logging counter and gauge metrics.
========================================================== =======================================================

Redefinitions
#############
======================================= =======================================
:zeek:type:`Log::ID`: :zeek:type:`enum` 
                                        
                                        * :zeek:enum:`Telemetry::LOG`
                                        
                                        * :zeek:enum:`Telemetry::LOG_HISTOGRAM`
======================================= =======================================

Events
######
================================================================= =========================================================
:zeek:id:`Telemetry::log_telemetry`: :zeek:type:`event`           Event triggered for every record in the stream.
:zeek:id:`Telemetry::log_telemetry_histogram`: :zeek:type:`event` Event triggered for every record in the histogram stream.
================================================================= =========================================================

Hooks
#####
======================================================================== =======================================================
:zeek:id:`Telemetry::log_policy`: :zeek:type:`Log::PolicyHook`           A default logging policy hook for the stream.
:zeek:id:`Telemetry::log_policy_histogram`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the histogram stream.
======================================================================== =======================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Telemetry::log_interval
   :source-code: policy/frameworks/telemetry/log.zeek 12 12

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min``

   How often metrics are reported.

.. zeek:id:: Telemetry::log_prefixes
   :source-code: policy/frameworks/telemetry/log.zeek 23 23

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "process",
            "zeek"
         }


   Only metrics with prefixes in this set will be included in the
   :file:`telemetry.log` and :file:`telemetry_histogram.log` files
   by default. Setting this option to an empty set includes all
   prefixes.
   
   For more fine-grained customization, setting this option to an
   empty set and implementing the :zeek:see:`Telemetry::log_policy`
   and :zeek:see:`Telemetry::log_policy_histogram` hooks to filter
   individual records is recommended.

Types
#####
.. zeek:type:: Telemetry::HistogramInfo
   :source-code: policy/frameworks/telemetry/log.zeek 51 78

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp of reporting.


   .. zeek:field:: peer :zeek:type:`string` :zeek:attr:`&log`

      Peer that generated this log.


   .. zeek:field:: name :zeek:type:`string` :zeek:attr:`&log`

      The name of the metric.


   .. zeek:field:: labels :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log`

      The names of the individual labels.


   .. zeek:field:: label_values :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log`

      The values of the labels as listed in ``labels``.


   .. zeek:field:: bounds :zeek:type:`vector` of :zeek:type:`double` :zeek:attr:`&log`

      The bounds of the individual buckets


   .. zeek:field:: values :zeek:type:`vector` of :zeek:type:`double` :zeek:attr:`&log`

      The number of observations within each individual bucket.


   .. zeek:field:: sum :zeek:type:`double` :zeek:attr:`&log`

      The sum over all observations


   .. zeek:field:: observations :zeek:type:`double` :zeek:attr:`&log`

      The total number of observations.


   Record type used for logging histogram metrics.

.. zeek:type:: Telemetry::Info
   :source-code: policy/frameworks/telemetry/log.zeek 26 48

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp of reporting.


   .. zeek:field:: peer :zeek:type:`string` :zeek:attr:`&log`

      Peer that generated this log.


   .. zeek:field:: metric_type :zeek:type:`string` :zeek:attr:`&log`

      Contains the value "counter" or "gauge" depending on
      the underlying metric type.


   .. zeek:field:: name :zeek:type:`string` :zeek:attr:`&log`

      The name of the metric.


   .. zeek:field:: labels :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log`

      The names of the individual labels.


   .. zeek:field:: label_values :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log`

      The values of the labels as listed in ``labels``.


   .. zeek:field:: value :zeek:type:`double` :zeek:attr:`&log`

      The value of this metric.


   Record type used for logging counter and gauge metrics.

Events
######
.. zeek:id:: Telemetry::log_telemetry
   :source-code: policy/frameworks/telemetry/log.zeek 87 87

   :Type: :zeek:type:`event` (rec: :zeek:type:`Telemetry::Info`)

   Event triggered for every record in the stream.

.. zeek:id:: Telemetry::log_telemetry_histogram
   :source-code: policy/frameworks/telemetry/log.zeek 90 90

   :Type: :zeek:type:`event` (rec: :zeek:type:`Telemetry::HistogramInfo`)

   Event triggered for every record in the histogram stream.

Hooks
#####
.. zeek:id:: Telemetry::log_policy
   :source-code: policy/frameworks/telemetry/log.zeek 81 81

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

.. zeek:id:: Telemetry::log_policy_histogram
   :source-code: policy/frameworks/telemetry/log.zeek 84 84

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the histogram stream.


