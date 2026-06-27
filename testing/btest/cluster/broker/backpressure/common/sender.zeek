# The sender fires batches of one-way ping events to a receiver to make it
# consume buffer space. An included epoch counter tracks how often we'receiving
# backpressure-induced unpeerings. While this is happening, the sender also
# receives ping events (of a different type) from the manager, which it echoes
# back to it. This verifies that the sender itself does not lock up. Messaging
# to stdout provides status updates.

@load base/frameworks/telemetry
@load ./common.zeek

global padding: string = string_fill(512, "1234567890"); # To eat buffer space
global ping_ival: interval = 0.01sec;

# Number of pings to send in one batch. This triggers overflow much more
# quickly, since buffer limits operate on message granularity.
global ping_batch = 20;

global epoch = 0; # Epochs increase with every backpressure-triggered de-peering
global counter = 0; # A counter for each ping to the receiver.

# A ping from manager to the sender that the sender echoes back, to verify
# liveness of that peering. This should always keep chugging -- if not, it means
# the sender's I/O troubles propagate to the manager: global lockup.
global manager_ping: event(ctr: count);

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( "caf::sec::backpressure_overflow" !in msg )
		return;

	# This event & message is our signal that we're no longer peered with
	# the receiver. Unwedge it. We keep sending pings and bump up the epoch
	# to distinguish before/after the de-peering.
	system(fmt("touch %s", unwedge_file));

	++epoch;
	print fmt("%s unpeered, epoch now %d", current_time(), epoch);
	}

hook Cluster::log_policy(info: Cluster::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( "removed due to backpressure" in info$message )
		print fmt("%s %s backpressure reported", current_time(), info$node);
	}

# This comes from the manager. We echo it back.
event manager_ping(ctr: count) &is_used
	{
	Cluster::publish(Cluster::manager_topic, manager_ping, ctr);
	}

event driver()
	{
	local i = 0;
	while ( ++i < ping_batch )
		Cluster::publish(ping_topic, ping, epoch, ++counter, padding);

	print trace_file, fmt("%s epoch %d, batch published", current_time(), epoch);
	schedule ping_ival { driver() };
	}

event zeek_init()
	{
	schedule ping_ival { driver() };
	}

event zeek_done()
	{
	local metrics = Telemetry::collect_metrics("zeek", "broker_backpressure_disconnects_total");

	if ( |metrics| > 0 && metrics[0]$value > 0.0 )
		print fmt("%s backpressure disconnect %s in telemetry",
		          current_time(), metrics[0]$label_values);
	}
