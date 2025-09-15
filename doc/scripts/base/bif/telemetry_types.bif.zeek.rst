:tocdepth: 3

base/bif/telemetry_types.bif.zeek
=================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Telemetry


:Namespaces: GLOBAL, Telemetry

Summary
~~~~~~~
Types
#####
===================================================== ================================================================
:zeek:type:`Telemetry::MetricType`: :zeek:type:`enum` An enum that specifies which type of metric you're operating on.
===================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Telemetry::MetricType
   :source-code: base/bif/telemetry_types.bif.zeek 8 8

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Telemetry::COUNTER Telemetry::MetricType

         Counters track entities that increment over time.

      .. zeek:enum:: Telemetry::GAUGE Telemetry::MetricType

         Gauges track entities that fluctuate over time.

      .. zeek:enum:: Telemetry::HISTOGRAM Telemetry::MetricType

         Histograms group observations into predefined bins.

   An enum that specifies which type of metric you're operating on.


