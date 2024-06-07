module Telemetry;

# This file contains the options for the Telemetry framework. These are kept
# separately so that they can be loaded in bare mode without loading all of
# the rest of the framework. This allows things like the plugins.hooks test
# to see the options without needing the rest.

export {
	## Address used to make metric data available to Prometheus scrapers via
	## HTTP.
	const metrics_address = getenv("ZEEK_DEFAULT_LISTEN_ADDRESS") &redef;

	## Port used to make metric data available to Prometheus scrapers via
	## HTTP.
	const metrics_port = 0/unknown &redef;

	## ID for the metrics exporter. This is used as the 'endpoint' label
	## value when exporting data to Prometheus. In a cluster setup, this
	## defaults to the name of the node in the cluster configuration.
	const metrics_endpoint_name = "" &redef;
}
