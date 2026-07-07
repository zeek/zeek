# The sender fires batches of one-way ping events to a receiver to make it
# consume buffer space. This version tracks dropped messages via telemetry.

@load base/frameworks/telemetry

global padding: string = string_fill(512, "1234567890"); # To eat buffer space
global ping_ival: interval = 0.01sec;

# Number of pings to send in one batch. This triggers overflow much more
# quickly, since buffer limits operate on message granularity.
global ping_batch = 20;

global epoch = 0; # The epoch becomes 1 once we've noticed backpressure overflow
global counter = 0; # A counter for each ping to the receiver.
global batches = 0; # A counter for the number of batches we've sent off.

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

	++batches;

	if ( epoch == 0 )
		{
		local metrics = Telemetry::collect_metrics("zeek", "broker_peer_buffer_overflows_total");

		# Simply look for the first metric that reports a drop. It
		# should be the worker <-> proxy one -- otherwise there's
		# something funky happening to the test and if we pick that
		# up via a baseline deviation, that's okay.
		for ( _, m in metrics )
			{
			if ( m$value == 0.0 )
				next;

			print fmt("%s backpressure overflows %s in telemetry",
			          current_time(), m$label_values);

			# Unwedge the receiver.
			system(fmt("touch %s", unwedge_file));
			epoch = 1;
			break;
			}
		}

	print trace_file, fmt("%s epoch %d, batch %d published to %s", current_time(), epoch, batches, ping_topic);
	schedule ping_ival { driver() };
	}

event Cluster::node_up(name: string, id: string)
	{
	# Start sending pings when the receiver is up and running.
	if ( (ping_topic == Cluster::proxy_topic && name == "proxy-1") ||
	     (ping_topic == Cluster::worker_topic && name == "worker-1") )
		schedule ping_ival { driver() };
	}
