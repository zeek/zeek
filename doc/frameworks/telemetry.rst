.. _histogram_quantile(): https://prometheus.io/docs/prometheus/latest/querying/functions/#histogram_quantile
.. _Prometheus: https://prometheus.io
.. _Prometheus Getting Started Guide: https://prometheus.io/docs/prometheus/latest/getting_started/
.. _Prometheus Metric Types: https://prometheus.io/docs/concepts/metric_types/
.. _Prometheus HTTP Service Discovery: https://prometheus.io/docs/prometheus/latest/http_sd/
.. _prometheus-cpp: https://github.com/jupp0r/prometheus-cpp

.. _framework-telemetry:

===================
Telemetry Framework
===================

.. note::

   This framework changed considerably with Zeek 7, and is not API-compatible
   with earlier versions.  While earlier versions relied on an implementation
   in :ref:`Broker <broker-framework>`, Zeek now maintains its
   own implementation, building on `prometheus-cpp`_, with Broker adding its
   telemetry to Zeek's internal registry of metrics.

The telemetry framework continuously collects metrics during Zeek's operation,
and provides ways to export this telemetry to third-party consumers. Zeek ships
with a pre-defined set of metrics and allows you to add your own, via
script-layer and in-core APIs you use to instrument relevant parts of the
code. Metrics target Zeek's operational behavior, or track characteristics of
monitored traffic. Metrics are not an additional export vehicle for Zeek's
various regular logs. Zeek's telemetry data model closely resembles that of
`Prometheus`_, and supports its text-based exposition format for scraping by
third-party collectors.

This section outlines usage examples, and gives brief API examples for
composing your own metrics. Head to the :zeek:see:`Telemetry` API documentation
for more details.

Metric Types
============

Zeek supports the following metric types:

  Counter
    A continuously increasing value, resetting on process restart.
    Examples of counters are the number of log writes since process start,
    packets processed, or ``process_seconds`` representing CPU usage.

  Gauge
    A gauge metric is a numerical value that can increase and decrease
    over time. Examples are table sizes or the :zeek:see:`val_footprint`
    of Zeek script values over the lifetime of the process. More general
    examples include a temperature or memory usage.

  Histogram
    Pre-configured buckets of observations with corresponding counts.
    Examples of histograms are connection durations, delays, or transfer
    sizes. Generally, it is useful to know the expected range and distribution
    of such values, as the bounds of a histogram's buckets are defined when
    this metric gets created.

Zeek uses :zeek:type:`double` throughout to track metric values. Since
terminology around telemetry can be complex, it helps to know a few additional
terms:

  Labels
    A given metric sometimes doesn't exist in isolation, but comes with
    additional labeling to disambiguate related observations. For example, Zeek
    ships with gauge called ``zeek_active_sessions`` that labels counts for TCP,
    UDP, and other transport protocols separately. Labels have a name (for
    example, "protocol") to refer to value (such as "tcp"). A metric can have
    multiple labels. Labels are thus a way to associate textual information with
    the numerical values of metrics.

  Family
    The set of such metrics, differing only by their labeling, is a known as a
    Family. Zeek's script-layer metrics API lets you operate on individual
    metrics and families.

Zeek has no equivalent to Prometheus's Summary type. A good reference to
consult for more details is the official `Prometheus Metric Types`_
documentation.

Cluster Considerations
======================

When running Zeek as a cluster, every node maintains its own metrics registry,
independently of the other nodes. Zeek does not automatically synchronize,
centralize, or aggregate metrics across the cluster. Instead, it adds the name
of the node a particular metric originated from at collection time, leaving any
aggregation to post-processing where desired.

.. note::

   This is a departure from the design in earlier versions of Zeek, which could
   (either by default, or after activation) centralize metrics in the cluster's
   manager node.

Accordingly, the :zeek:see:`Telemetry::collect_metrics` and
:zeek:see:`Telemetry::collect_histogram_metrics` functions only return
node-local metrics.

Metrics Export
==============

Zeek supports two mechanisms for exporting telemetry: traditional logs, and
Prometheus-compatible endpoints for scraping by a third-party service. We cover
them in turn.

Zeek Logs
---------

Zeek can export current metrics continuously via :file:`telemetry.log` and
:file:`telemetry_histogram.log`. It does not do so by default. To enable, load the
policy script ``frameworks/telemetry/log`` on the command line, or via
``local.zeek``.

The :zeek:see:`Telemetry::Info` and :zeek:see:`Telemetry::HistogramInfo` records
define the logs.  Both records include a ``peer`` field that conveys the
cluster node the metric originated from.

By default, Zeek reports current telemetry every 60 seconds, as defined by the
:zeek:see:`Telemetry::log_interval`, which you're free to adjust.

Also, by default only metrics with the ``prefix`` (namespace) ``zeek`` and
``process`` are included in above logs. If you add new metrics with your own
prefix and expect these to be included, redefine the
:zeek:see:`Telemetry::log_prefixes` option::

    @load frameworks/telemetry/log

    redef Telemetry::log_prefixes += { "my_prefix" };

Clearing the set will cause all metrics to be logged. As with any logs, you may
employ :ref:`policy hooks <logging-filtering-log-records>`,
:zeek:see:`Telemetry::log_policy` and
:zeek:see:`Telemetry::log_policy_histogram`, to define potentially more granular
filtering.

Native Prometheus Export
------------------------

Every Zeek process, regardless of whether it's running long-term standalone or
as part of a cluster, can run an HTTP server that renders current telemetry in
Prometheus's `text-based exposition format
<https://github.com/prometheus/docs/blob/main/docs/instrumenting/exposition_formats.md>`_.

The :zeek:see:`Telemetry::metrics_port` variable controls this behavior. Its
default of ``0/unknown`` disables exposing the port; setting it to another TCP
port will enable it. In clusterized operation, the cluster topology can specify
each node's metrics port via the corresponding :zeek:see:`Cluster::Node` field,
and the framework will adjust ``Telemetry::metrics_port`` accordingly.  Both
zeekctl and the management framework let you define specific ports and can also
auto-populate their values, similarly to Broker's listening ports.

To query a node's telemetry, point an HTTP client or Prometheus scraper at the
node's metrics port::

  $ curl -s http://<node>:<node-metrics-port>/metrics
  # HELP exposer_transferred_bytes_total Transferred bytes to metrics services
  # TYPE exposer_transferred_bytes_total counter
  exposer_transferred_bytes_total 0
  ...
  # HELP zeek_event_handler_invocations_total Number of times the given event handler was called
  # TYPE zeek_event_handler_invocations_total counter
  zeek_event_handler_invocations_total{endpoint="manager",name="run_sync_hook"} 2
  ...

To simplify telemetry collection from all nodes in a cluster, Zeek supports
`Prometheus HTTP Service Discovery`_ on the manager node. Using this approach, the
endpoint ``http://<manager>:<manager-metrics-port>/services.json`` returns a
JSON data structure that itemizes all metrics endpoints in the
cluster. Prometheus scrapers supporting service discovery then proceed to
collect telemetry from the listed endpoints in turn.

The following is an example service discovery scrape config entry within
Prometheus server's ``prometheus.yml`` configuration file::

    ...
    scrape_configs:
      - job_name: zeek-discovery
        scrape_interval: 5s
        http_sd_configs:
          - url: http://localhost:9991/services.json
            refresh_interval: 10s

See the `Prometheus Getting Started Guide`_ for additional information.

.. note::

   .. versionchanged:: 7.0

   The built-in aggregation for Zeek telemetry to the manager node has been
   removed, in favor of the Prometheus-compatible service discovery
   endpoint. The new approach requires cluster administrators to manage access
   to the additional ports. However, it allows Prometheus to conduct the
   aggregation, instead of burdening the Zeek manager with it, which has
   historically proved expensive.

If these setups aren't right for your environment, there's the possibility to
redefine the options in ``local.zeek`` to something more suitable. For example,
the following snippet selects the metrics port of each Zeek process relative
to the cluster port used in ``cluster-layout.zeek``::

    @load base/frameworks/cluster

    global my_node = Cluster::nodes[Cluster::node];
    global my_metrics_port = count_to_port(port_to_count(my_node$p) - 1000, tcp);

    redef Telemetry::metrics_port = my_metrics_port;


Examples of Metrics Application
===============================

Counting Log Writes per Stream
------------------------------

In combination with the :zeek:see:`Log::log_stream_policy` hook, it is
straightforward to record :zeek:see:`Log::write` invocations over the dimension
of the :zeek:see:`Log::ID` value.  This section shows three different approaches
to do this. Which approach is most applicable depends mostly on the expected
script layer performance overhead for updating the metric.  For example, calling
:zeek:see:`Telemetry::counter_with` and :zeek:see:`Telemetry::counter_inc`
within a handler of a high-frequency event may be prohibitive, while for a
low-frequency event it's unlikely to matter.

Assuming a :zeek:see:`Telemetry::metrics_port` of 9090, querying the Prometheus
endpoint using ``curl`` provides output resembling the following for each of
the three approaches.

.. code-block::

   $ curl -s localhost:9090/metrics | grep log_writes
   # HELP zeek_log_writes_total Number of log writes per stream
   # TYPE zeek_log_writes_total counter
   zeek_log_writes_total{endpoint="zeek",log_id="packetfilter_log"} 1
   zeek_log_writes_total{endpoint="zeek",log_id="loadedscripts_log"} 477
   zeek_log_writes_total{endpoint="zeek",log_id="stats_log"} 1
   zeek_log_writes_total{endpoint="zeek",log_id="dns_log"} 200
   zeek_log_writes_total{endpoint="zeek",log_id="ssl_log"} 9
   zeek_log_writes_total{endpoint="zeek",log_id="conn_log"} 215
   zeek_log_writes_total{endpoint="zeek",log_id="captureloss_log"} 1

The above shows a family of 7 ``zeek_log_writes_total`` metrics, each with an
``endpoint`` label (here, ``zeek``, which would be a cluster node name if
scraped from a Zeek cluster) and a ``log_id`` one.

Immediate
^^^^^^^^^

The following example creates a global counter family object and uses
the :zeek:see:`Telemetry::counter_family_inc` helper to increment the
counter metric associated with a string representation of the :zeek:see:`Log::ID`
value.


.. literalinclude:: telemetry/log-writes-immediate.zeek
   :caption: log-writes-immediate.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

With a few lines of scripting code, Zeek now track log writes per stream
ready to be scraped by a Prometheus server.


Cached
^^^^^^

For cases where creating the label value (stringification, :zeek:see:`gsub` and :zeek:see:`to_lower`)
and instantiating the label vector as well as invoking the
:zeek:see:`Telemetry::counter_family_inc` methods cause too much
performance overhead, the counter instances can also be cached in a lookup table.
The counters can then be incremented with :zeek:see:`Telemetry::counter_inc`
directly.

.. literalinclude:: telemetry/log-writes-cached.zeek
   :caption: log-writes-cached.zeek
   :language: zeek
   :linenos:
   :tab-width: 4


For metrics without labels, the metric instances can also be cached as global
variables directly. The following example counts the number of http requests.

.. literalinclude:: telemetry/global-http-counter.zeek
   :caption: global-http-counter.zeek
   :language: zeek
   :linenos:
   :tab-width: 4


Sync
^^^^

In case the scripting overhead of the previous approach is still too high,
individual writes (or events) can be tracked in a table or global variable
and then synchronized / mirrored to concrete counter and gauge instances
during execution of the :zeek:see:`Telemetry::sync` hook.

.. literalinclude:: telemetry/log-writes-sync.zeek
   :caption: log-writes-sync.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

For tracking log writes, this is unlikely to be required (and Zeek exposes
various logging natively through the framework already), but for updating
metrics within high frequency events that otherwise have low script processing
overhead, it's a valuable approach.


.. versionchanged:: 7.1

The :zeek:see:`Telemetry::sync` hook is invoked on-demand only. Either when
one of the :zeek:see:`Telemetry::collect_metrics`
or :zeek:see:`Telemetry::collect_histogram_metrics` functions is invoked, or
when querying Prometheus endpoint. It's an error to call either of the
collection BiFs within the :zeek:see:`Telemetry::sync` hook and results
in a reporter warning.


.. note::

   In versions before Zeek 7.1, :zeek:see:`Telemetry::sync` was invoked on a
   fixed schedule, potentially resulting in stale metrics at collection time,
   as well as generating small runtime overhead when metrics are not collected.

Table Sizes
-----------

It can be useful to expose the size of tables as metrics, as they often
indicate the approximate amount of state maintained in memory.
As table sizes may increase and decrease, a :zeek:see:`Telemetry::Gauge`
is appropriate for this purpose.

The following example records the size of the :zeek:see:`Tunnel::active` table
and its footprint with two gauges. The gauges are updated during the
:zeek:see:`Telemetry::sync` hook. Note, there are no labels in use, both
gauge instances are simple globals.

.. literalinclude:: telemetry/table-size-tracking.zeek
   :caption: log-writes-sync.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

Example representation of these metrics when querying the Prometheus endpoint:

.. code-block::

   $ curl -s localhost:9090/metrics | grep tunnel
   # HELP zeek_monitored_tunnels_active_footprint Footprint of the Tunnel::active table
   # TYPE zeek_monitored_tunnels_active_footprint gauge
   zeek_monitored_tunnels_active_footprint{endpoint="zeek"} 324
   # HELP zeek_monitored_tunnels_active Number of currently active tunnels as tracked in Tunnel::active
   # TYPE zeek_monitored_tunnels_active gauge
   zeek_monitored_tunnels_active{endpoint="zeek"} 12


Instead of tracking footprints per variable, :zeek:see:`global_container_footprints`,
could be leveraged to track all global containers at once, using the variable
name as label.

Connection Durations as Histogram
---------------------------------

To track the distribution of certain measurements, a :zeek:see:`Telemetry::Histogram`
can be used. The histogram's buckets have to be preconfigured.

The following example observes the duration of each connection that Zeek has
monitored.

.. literalinclude:: telemetry/connection-durations.zeek
   :caption: connection-durations.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

Due to the way Prometheus represents histograms and the fact that durations
are broken down by protocol and service in the given example, the resulting
representation becomes rather verbose.

.. code-block::

   $ curl -s localhost:9090/metrics | grep monitored_connection_duration
   # HELP zeek_monitored_connection_duration_seconds Duration of monitored connections
   # TYPE zeek_monitored_connection_duration_seconds histogram
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="0.1"} 970
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="1"} 998
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="10"} 1067
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="30"} 1108
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="60"} 1109
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="+Inf"} 1109
   zeek_monitored_connection_duration_seconds_sum{endpoint="zeek",proto="udp",service="dns"} 1263.085691
   zeek_monitored_connection_duration_seconds_count{endpoint="zeek",proto="udp",service="dns"} 1109
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="0.1"} 16
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="1"} 54
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="10"} 56
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="30"} 57
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="60"} 57
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="+Inf"} 57


To work with histogram data, Prometheus provides specialized query functions.
For example `histogram_quantile()`_.

Note, when using data from :file:`conn.log` and post-processing, a proper
histogram of connection durations can be calculated and possibly preferred.
The above example is meant for demonstration purposes. Histograms may be
primarily be useful for Zeek operational metrics such as processing times
or queueing delays, response times to external systems, etc.


Exporting the Zeek Version
--------------------------

A common pattern in the Prometheus ecosystem is to expose the version
information of the running process as gauge metric with a value of 1.

The following example does just that with a Zeek script:

.. literalinclude:: telemetry/version.zeek
   :caption: version.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

In Prometheus's exposition format, this turns into the following:

.. code-block::

   $ curl -s localhost:9090/metrics | grep version
   # HELP zeek_version_info The Zeek version
   # TYPE zeek_version_info gauge
   zeek_version_info{beta="true",commit="0",debug="true",major="7",minor="0",patch="0",version_number="70000",version_string="7.0.0-rc4-debug"} 1
   zeek_version_info{beta="false",commit="289",debug="true",endpoint="zeek",major="5",minor="1",patch="0",version_number="50100",version_string="5.1.0-dev.289-debug"} 1.000000


Zeek already ships with this gauge, via
:doc:`/scripts/base/frameworks/telemetry/main.zeek`. There is no need to add
above snippet to your site.
