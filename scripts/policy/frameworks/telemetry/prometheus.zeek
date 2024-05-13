##! In a cluster configuration, open the port number for metrics
##! from the cluster node configuration for exporting data to
##! Prometheus.
##!
##! For customization or disabling, redef the involved Telemetry options
##! again. Specifically, to disable listening on port 9911, set
##! :zeek:see:`Telemetry::metrics_port` to `0/unknown` again.
##!
##! The manager node will also provide a ``/services.json`` endpoint
##! for the HTTP Service Discovery system in Prometheus to use for
##! configuration. This endpoint will include information for all of
##! the other nodes in the cluster.
@load base/frameworks/cluster

@if ( Cluster::is_enabled() )

redef Telemetry::metrics_endpoint_name = Cluster::node;

@if ( Cluster::local_node_metrics_port() != 0/unknown )
redef Telemetry::metrics_port = Cluster::local_node_metrics_port();
@endif

@endif
