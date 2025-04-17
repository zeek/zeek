# Additional Broker-specific metrics that use Zeek cluster-level node names.

@load base/frameworks/telemetry

module Cluster;

global broker_peer_buffer_levels_gf = Telemetry::register_gauge_family([
    $prefix="zeek",
    $name="broker-peer-buffer-levels",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of messages queued in Broker's per-peer send buffers",
]);

global broker_peer_buffer_overflows_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="broker-peer-buffer-overflows",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of overflows in Broker's per-peer send buffers",
]);

hook Telemetry::sync()
	{
	local peers: table[string] of count = Broker::peer_buffer_levels();
	local nn: NamedNode;

	for ( peer, level in peers )
		{
		# Translate the Broker IDs to Zeek-level node names. We skip
		# telemetry for peers where this mapping fails, i.e. ones for
		# connections to external systems.
		nn = nodeid_to_node(peer);

		if ( |nn$name| > 0 )
			Telemetry::gauge_family_set(broker_peer_buffer_levels_gf,
			    vector(nn$name), level);
		}

	peers = Broker::peer_buffer_overflows();

	for ( peer, overflows in peers )
		{
		nn = nodeid_to_node(peer);

		if ( |nn$name| > 0 )
			Telemetry::counter_family_set(broker_peer_buffer_overflows_cf,
			    vector(nn$name), overflows);
		}
	}
