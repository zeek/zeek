:orphan:

Package: base/frameworks/telemetry
==================================


:doc:`/scripts/base/frameworks/telemetry/options.zeek`


:doc:`/scripts/base/frameworks/telemetry/__load__.zeek`


:doc:`/scripts/base/frameworks/telemetry/main.zeek`

   Module for recording and querying metrics. This modules wraps
   the lower-level telemetry.bif functions.
   
   Metrics will be exposed through a Prometheus HTTP endpoint when
   enabled by setting :zeek:see:`Telemetry::metrics_port`.

