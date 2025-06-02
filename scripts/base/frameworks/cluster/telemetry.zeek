## Module for enabling cluster telemetry.
module Cluster::Telemetry;

export {

	type Type: enum {
		NONE,
		DEBUG,
		PRODUCTION,
	};

	## The default telemetry to enable.
	const telemetry_type = PRODUCTION &redef;

	## Table for normalizing of topics that contain random parts.
	const topic_normalizations: table[pattern] of string = {
		[/^zeek\.cluster\.nodeid\..*/] = "zeek.cluster.nodeid.__normalized__",
		[/^zeek\/cluster\/nodeid\/.*/] = "zeek/cluster/nodeid/__normalized__",
	} &ordered;

	## For the DEBUG metrics, the buckets to use.
	const message_size_bounds: vector of double = {
		10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0,
	};
}
