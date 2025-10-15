:tocdepth: 3

base/frameworks/telemetry/options.zeek
======================================
.. zeek:namespace:: Telemetry


:Namespace: Telemetry

Summary
~~~~~~~
Redefinable Options
###################
==================================================================================== =====================================================================
:zeek:id:`Telemetry::metrics_address`: :zeek:type:`string` :zeek:attr:`&redef`       Address used to make metric data available to Prometheus scrapers via
                                                                                     HTTP.
:zeek:id:`Telemetry::metrics_endpoint_name`: :zeek:type:`string` :zeek:attr:`&redef` ID for the metrics exporter.
:zeek:id:`Telemetry::metrics_port`: :zeek:type:`port` :zeek:attr:`&redef`            Port used to make metric data available to Prometheus scrapers via
                                                                                     HTTP.
==================================================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Telemetry::metrics_address
   :source-code: base/frameworks/telemetry/options.zeek 11 11

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Address used to make metric data available to Prometheus scrapers via
   HTTP.

.. zeek:id:: Telemetry::metrics_endpoint_name
   :source-code: base/frameworks/telemetry/options.zeek 20 20

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   ID for the metrics exporter. This is used as the 'endpoint' label
   value when exporting data to Prometheus. In a cluster setup, this
   defaults to the name of the node in the cluster configuration.

.. zeek:id:: Telemetry::metrics_port
   :source-code: base/frameworks/telemetry/options.zeek 15 15

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0/unknown``

   Port used to make metric data available to Prometheus scrapers via
   HTTP. The default value means Zeek won't expose the port.


