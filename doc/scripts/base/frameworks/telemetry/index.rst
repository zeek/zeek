:orphan:

Package: base/frameworks/telemetry
==================================


:doc:`/scripts/base/frameworks/telemetry/options.zeek`

   Configurable settings for the Telemetry framework.

   These reside separately from the main framework so that they can be loaded
   in bare mode without all of the framework. This allows things like the
   plugins.hooks test to see the options without needing the rest.

:doc:`/scripts/base/frameworks/telemetry/__load__.zeek`


:doc:`/scripts/base/frameworks/telemetry/main.zeek`

   Module for recording and querying metrics. This modules wraps
   the lower-level telemetry.bif functions.

   Metrics will be exposed through a Prometheus HTTP endpoint when
   enabled by setting :zeek:see:`Telemetry::metrics_port`.

