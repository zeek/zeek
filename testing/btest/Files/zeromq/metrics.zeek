module Cluster::Backend::ZeroMQ;

export {
	global xpub_drops: function(): count;
	global onloop_drops: function(): count;
}

function xpub_drops(): count
	{
	local ms = Telemetry::collect_metrics("zeek", "cluster_zeromq_xpub_drops_total");
	assert |ms| == 1, fmt("%s", |ms|);
	return double_to_count(ms[0]$value);
	}

function onloop_drops(): count
	{
	local ms = Telemetry::collect_metrics("zeek", "cluster_zeromq_onloop_drops_total");
	assert |ms| == 1, fmt("%s", |ms|);
	return double_to_count(ms[0]$value);
	}
