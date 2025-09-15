:tocdepth: 3

base/frameworks/telemetry/options.zeek
======================================
.. zeek:namespace:: Telemetry

Configurable settings for the Telemetry framework.

These reside separately from the main framework so that they can be loaded
in bare mode without all of the framework. This allows things like the
plugins.hooks test to see the options without needing the rest.

:Namespace: Telemetry

Summary
~~~~~~~
Redefinable Options
###################
===================================================================================== =====================================================================
:zeek:id:`Telemetry::metrics_address`: :zeek:type:`string` :zeek:attr:`&redef`        Address used to make metric data available to Prometheus scrapers via
                                                                                      HTTP.
:zeek:id:`Telemetry::metrics_endpoint_label`: :zeek:type:`string` :zeek:attr:`&redef` Every metric automatically receives a label with the following name
                                                                                      and the metrics_endpoint_name as value to identify the originating
                                                                                      cluster node.
:zeek:id:`Telemetry::metrics_endpoint_name`: :zeek:type:`string` :zeek:attr:`&redef`  ID for the metrics exporter.
:zeek:id:`Telemetry::metrics_port`: :zeek:type:`port` :zeek:attr:`&redef`             Port used to make metric data available to Prometheus scrapers via
                                                                                      HTTP.
===================================================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Telemetry::metrics_address
   :source-code: base/frameworks/telemetry/options.zeek 12 12

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Address used to make metric data available to Prometheus scrapers via
   HTTP.

.. zeek:id:: Telemetry::metrics_endpoint_label
   :source-code: base/frameworks/telemetry/options.zeek 23 23

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"node"``

   Every metric automatically receives a label with the following name
   and the metrics_endpoint_name as value to identify the originating
   cluster node.
   The label was previously hard-code as "endpoint", and that's why
   the variable is called the way it is, but "node" is the better label.

.. zeek:id:: Telemetry::metrics_endpoint_name
   :source-code: base/frameworks/telemetry/options.zeek 28 28

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   ID for the metrics exporter. This is used as the 'endpoint' label
   value when exporting data to Prometheus. In a cluster setup, this
   defaults to the name of the node in the cluster configuration.

.. zeek:id:: Telemetry::metrics_port
   :source-code: base/frameworks/telemetry/options.zeek 16 16

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0/unknown``

   Port used to make metric data available to Prometheus scrapers via
   HTTP. The default value means Zeek won't expose the port.


