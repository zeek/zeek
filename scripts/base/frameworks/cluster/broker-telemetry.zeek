# Additional Broker-specific metrics that use Zeek cluster-level node names.

@load base/frameworks/telemetry

module Cluster;

## This gauge tracks the current number of locally queued messages in each
## Broker peering's send buffer. The "peer" label identifies the remote side of
## the peering, containing a Zeek cluster node name.
global broker_peer_buffer_messages_gf = Telemetry::register_gauge_family([
    $prefix="zeek",
    $name="broker-peer-buffer-messages",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of messages queued in Broker's send buffers",
]);

## This gauge tracks recent maximum queue lengths for each Broker peering's send
## buffer. Most of the time the send buffers are nearly empty, so this gauge
## helps understand recent bursts of messages.  "Recent" here means
## :zeek:see:`Broker::buffer_stats_reset_interval`. The time window advances in
## increments of at least the stats interval, not incrementally with every new
## observed message. That is, Zeek keeps a timestamp of when the window started,
## and once it notices that the interval has passed, it moves the start of the
## window to current time.
global broker_peer_buffer_recent_max_messages_gf = Telemetry::register_gauge_family([
    $prefix="zeek",
    $name="broker-peer-buffer-recent-max-messages",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Maximum number of messages recently queued in Broker's send buffers",
]);

## This counter tracks for each Broker peering the number of times its send
## buffer has overflowed. For the "disconnect" policy this can at most be 1,
## since Broker stops the peering at this time. For the "drop_oldest" and
## "drop_newest" policies (see :zeek:see:`Broker:peer_overflow_policy`) the count
## instead reflects the number of messages lost.
global broker_peer_buffer_overflows_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="broker-peer-buffer-overflows",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of overflows in Broker's send buffers",
]);

hook Telemetry::sync()
	{
	local peers = Broker::peering_stats();
	local nn: NamedNode;

	for ( peer, stats in peers )
		{
		# Translate the Broker IDs to Zeek-level node names. We skip
		# telemetry for peers where this mapping fails, i.e. ones for
		# connections to external systems.
		nn = nodeid_to_node(peer);

		if ( |nn$name| > 0 )
			{
			Telemetry::gauge_family_set(broker_peer_buffer_messages_gf,
			    vector(nn$name), stats$num_queued);
			Telemetry::gauge_family_set(broker_peer_buffer_recent_max_messages_gf,
			    vector(nn$name), stats$max_queued_recently);
			Telemetry::counter_family_set(broker_peer_buffer_overflows_cf,
			    vector(nn$name), stats$num_overflows);
			}
		}
	}
