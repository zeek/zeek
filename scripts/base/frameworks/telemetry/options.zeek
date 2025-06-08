##! Configurable settings for the Telemetry framework.
##!
##! These reside separately from the main framework so that they can be loaded
##! in bare mode without all of the framework. This allows things like the
##! plugins.hooks test to see the options without needing the rest.

module Telemetry;

export {
	## Address used to make metric data available to Prometheus scrapers via
	## HTTP.
	const metrics_address = getenv("ZEEK_DEFAULT_LISTEN_ADDRESS") &redef;

	## Port used to make metric data available to Prometheus scrapers via
	## HTTP. The default value means Zeek won't expose the port.
	const metrics_port = 0/unknown &redef;

	## Every metric automatically receives a label with the following name
	## and the metrics_endpoint_name as value to identify the originating
	## cluster node.
	## The label was previously hard-code as "endpoint", and that's why
	## the variable is called the way it is, but "node" is the better label.
	const metrics_endpoint_label = "node" &redef;

	## ID for the metrics exporter. This is used as the 'endpoint' label
	## value when exporting data to Prometheus. In a cluster setup, this
	## defaults to the name of the node in the cluster configuration.
	const metrics_endpoint_name = "" &redef;
}

# When running a cluster, use the metrics port from the cluster node
# configuration for exporting data to Prometheus.
#
# The manager node will also provide a ``/services.json`` endpoint
# for the HTTP Service Discovery system in Prometheus to use for
# configuration. This endpoint will include information for all of
# the other nodes in the cluster.

# We do this here, and not in main.zeek, to avoid ordering issues when loading
# the telemetry and cluster frameworks. This applies even in bare mode, per
# init-frameworks-and-bifs.zeek: the cluster's metrics ports need to be available
# for the redefs to assign the correct values.
@if ( Cluster::is_enabled() )
redef Telemetry::metrics_endpoint_name = Cluster::node;

@if ( Cluster::local_node_metrics_port() != 0/unknown )
redef Telemetry::metrics_port = Cluster::local_node_metrics_port();
@endif
@endif
