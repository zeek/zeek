# Additional Broker-specific metrics that use Zeek cluster-level node names.

@load base/frameworks/telemetry

module Cluster;

## This gauge tracks the current number of locally queued messages in each
## Broker peering's send buffer. The "peer" label identifies the remote side of
## the peering, containing a Zeek cluster node name.
global broker_peer_buffer_messages_gf = Telemetry::register_gauge_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="broker-peer-buffer-messages",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of messages queued in Broker's send buffers",
));

## This gauge tracks recent maximum queue lengths for each Broker peering's send
## buffer. Most of the time the send buffers are nearly empty, so this gauge
## helps understand recent bursts of messages.  "Recent" here means
## :zeek:see:`Broker::buffer_stats_reset_interval`. The time window advances in
## increments of at least the stats interval, not incrementally with every new
## observed message. That is, Zeek keeps a timestamp of when the window started,
## and once it notices that the interval has passed, it moves the start of the
## window to current time.
global broker_peer_buffer_recent_max_messages_gf = Telemetry::register_gauge_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="broker-peer-buffer-recent-max-messages",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Maximum number of messages recently queued in Broker's send buffers",
));

## This counter tracks for each Broker peering the number of times its send
## buffer has overflowed. For the "disconnect" policy this can at most be 1,
## since Broker stops the peering at this time. For the "drop_oldest" and
## "drop_newest" policies (see :zeek:see:`Broker:peer_overflow_policy`) the count
## instead reflects the number of messages lost.
global broker_peer_buffer_overflows_cf = Telemetry::register_counter_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="broker-peer-buffer-overflows",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of overflows in Broker's send buffers",
));


# A helper to track overflow counts over past peerings as well as the current
# one.  The peer_id field allows us to identify when the counter has reset: a
# Broker ID different from the one on file means it's a new peering.
type EpochData: record {
	peer_id: string;
	num_overflows: count &default=0;
	num_past_overflows: count &default=0;
};

# This maps from a cluster node name to its EpochData.
global peering_epoch_data: table[string] of EpochData;

hook Telemetry::sync()
	{
	local peers = Broker::peering_stats();
	local nn: NamedNode;
	local labels: vector of string;
	local ed: EpochData;

	for ( peer_id, stats in peers )
		{
		# Translate the Broker IDs to Zeek-level node names. We skip
		# telemetry for peers where this mapping fails, i.e. ones for
		# connections to external systems.
		nn = nodeid_to_node(peer_id);

		if ( |nn$name| == 0 )
			next;

		labels = vector(nn$name);

		Telemetry::gauge_family_set(broker_peer_buffer_messages_gf,
		    labels, stats$num_queued);
		Telemetry::gauge_family_set(broker_peer_buffer_recent_max_messages_gf,
		    labels, stats$max_queued_recently);

		if ( nn$name !in peering_epoch_data )
			peering_epoch_data[nn$name] = EpochData($peer_id=peer_id);

		ed = peering_epoch_data[nn$name];

		if ( peer_id != ed$peer_id )
			{
			# A new peering. Ensure that we account for overflows in
			# past ones. There is a risk here that we might have
			# missed a peering altogether if we scrape infrequently,
			# but re-peering should be a rare event.
			ed$peer_id = peer_id;
			ed$num_past_overflows += ed$num_overflows;
			}

		ed$num_overflows = stats$num_overflows;

		Telemetry::counter_family_set(broker_peer_buffer_overflows_cf,
		    labels, ed$num_past_overflows + ed$num_overflows);
		}
	}
