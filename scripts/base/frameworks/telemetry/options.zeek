module Telemetry;

# This file contains the options for the Telemetry framework. These are kept
# separately so that they can be loaded in bare mode without loading all of
# the rest of the framework. This allows things like the plugins.hooks test
# to see the options without needing the rest.

export {
	## Port used to make metric data available to Prometheus scrapers via
	## HTTP.  Zeek overrides any value provided in zeek_init or earlier at
	## startup if the environment variable ZEEK_METRICS_PORT is defined.
	const metrics_port = 0/unknown &redef;

	## Frequency for publishing scraped metrics to the target topic. Zeek
	## overrides any value provided in zeek_init or earlier at startup if
	## the environment variable ZEEK_METRICS_EXPORT_INTERVAL is defined.
	option metrics_export_interval = 1 sec;

	## Target topic for the metrics. Setting a non-empty string starts the
	## periodic publishing of local metrics. Zeek overrides any value
	## provided in zeek_init or earlier at startup if the environment
	## variable ZEEK_METRICS_EXPORT_TOPIC is defined.
	option metrics_export_topic = "";

	## Topics for the telmeetry framework for collecting metrics from other
	## peers in the network and including them in the output. Has no effect
	## when not exporting the metrics to Prometheus.
	##
	## Zeek overrides any value provided in zeek_init or earlier at startup
	## if the environment variable ZEEK_METRICS_IMPORT_TOPICS is defined.
	option metrics_import_topics: vector of string = vector();

	## ID for the metrics exporter. When setting a target topic for the
	## exporter, Broker sets this option to the suffix of the new topic
	## *unless* the ID is a non-empty string. Since setting a topic starts
	## the periodic publishing of events, we recommend setting the ID always
	## first or avoid setting it at all if the topic suffix serves as a
	## good-enough ID. Zeek overrides any value provided in zeek_init or
	## earlier at startup if the environment variable
	## ZEEK_METRICS_ENDPOINT_NAME is defined.
	option metrics_export_endpoint_name = "";

	## Selects prefixes from the local metrics. Only metrics with prefixes
	## listed in this variable are included when publishing local metrics.
	## Setting an empty vector selects *all* metrics.
	option metrics_export_prefixes: vector of string = vector();
}

# Needed for the __set methods below
@load base/bif/telemetry.bif

function update_metrics_export_interval(id: string, val: interval): interval
	{
	Telemetry::__set_metrics_export_interval(val);
	return val;
	}

function update_metrics_export_topic(id: string, val: string): string
	{
	Telemetry::__set_metrics_export_topic(val);
	return val;
	}

function update_metrics_import_topics(id: string, topics: vector of string): vector of string
	{
	Telemetry::__set_metrics_import_topics(topics);
	return topics;
	}

function update_metrics_export_endpoint_name(id: string, val: string): string
	{
	Telemetry::__set_metrics_export_endpoint_name(val);
	return val;
	}

function update_metrics_export_prefixes(id: string, filter: vector of string): vector of string
	{
	Telemetry::__set_metrics_export_prefixes(filter);
	return filter;
	}

event zeek_init()
	{
	# interval
	update_metrics_export_interval("Telemetry::metrics_export_interval",
	                               Telemetry::metrics_export_interval);
	Option::set_change_handler("Telemetry::metrics_export_interval",
	                           update_metrics_export_interval);
	# topic
	update_metrics_export_topic("Telemetry::metrics_export_topic",
	                            Telemetry::metrics_export_topic);
	Option::set_change_handler("Telemetry::metrics_export_topic",
	                           update_metrics_export_topic);
	# import topics
	update_metrics_import_topics("Telemetry::metrics_import_topics",
	                             Telemetry::metrics_import_topics);
	Option::set_change_handler("Telemetry::metrics_import_topics",
	                           update_metrics_import_topics);
	# endpoint name
	update_metrics_export_endpoint_name("Telemetry::metrics_export_endpoint_name",
	                                    Telemetry::metrics_export_endpoint_name);
	Option::set_change_handler("Telemetry::metrics_export_endpoint_name",
	                           update_metrics_export_endpoint_name);
	# prefixes
	update_metrics_export_prefixes("Telemetry::metrics_export_prefixes",
	                               Telemetry::metrics_export_prefixes);
	Option::set_change_handler("Telemetry::metrics_export_prefixes",
	                           update_metrics_export_prefixes);
	}
