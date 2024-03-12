module Telemetry;

# This file contains the options for the Telemetry framework. These are kept
# separately so that they can be loaded in bare mode without loading all of
# the rest of the framework. This allows things like the plugins.hooks test
# to see the options without needing the rest.

export {
	## Port used to make metric data available to Prometheus scrapers via
	## HTTP. Zeek overrides any value provided in zeek_init or earlier at
	## startup if the environment variable ZEEK_METRICS_PORT is defined.
	const metrics_port = 0/unknown &redef;

	## ID for the metrics exporter. When setting a target topic for the
	## exporter, Broker sets this option to the suffix of the new topic
	## *unless* the ID is a non-empty string. Since setting a topic starts
	## the periodic publishing of events, we recommend setting the ID always
	## first or avoid setting it at all if the topic suffix serves as a
	## good-enough ID. Zeek overrides any value provided in zeek_init or
	## earlier at startup if the environment variable
	## ZEEK_METRICS_ENDPOINT_NAME is defined.
	const metrics_endpoint_name = "" &redef;

	## Selects prefixes from the local metrics. Only metrics with prefixes
	## listed in this variable are included when publishing local metrics.
	## Setting an empty vector selects *all* metrics.
	const metrics_export_prefixes: vector of string = vector() &redef;
}
