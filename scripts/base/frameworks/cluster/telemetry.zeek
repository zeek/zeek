## Module for cluster telemetry.
module Cluster::Telemetry;

export {
	type Type: enum {
		## Creates counter metrics for incoming and for outgoing
		## events without labels.
		INFO,
		## Creates counter metrics for incoming and outgoing events
		## labeled with handler and normalized topic names.
		VERBOSE,
		## Creates histogram metrics using the serialized message size
		## for events, labeled by topic, handler and script location
		## (outgoing only).
		DEBUG,
	};

	## The telemetry types to enable for the core backend.
	const core_metrics: set[Type] = {
		INFO,
	} &redef;

	## The telemetry types to enable for WebSocket backends.
	const websocket_metrics: set[Type] = {
		INFO,
	} &redef;

	## Table used for normalizing topic names that contain random parts.
	## Map to an empty string to skip recording a specific metric
	## completely.
	const topic_normalizations: table[pattern] of string = {
		[/^zeek\/cluster\/nodeid\/.*/] = "zeek/cluster/nodeid/__normalized__",
	} &ordered &redef;

	## For the DEBUG metrics, the histogram buckets to use.
	const message_size_bounds: vector of double = {
		10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0,
	} &redef;
}
