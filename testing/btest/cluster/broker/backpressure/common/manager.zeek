# The manager sends its own type of low-frequency pings to the sender and tracks
# their roundtrip back to itself. When response pings go missing for too long, the
# manager concludes the sender is locked up. This should never happen because
# Broker tracks backpressure per peering, not globally.

@load ./common.zeek

global ping_ival: interval = 0.5sec;
global max_ping_delay: interval = 20sec;
global last_ping_rx: time = 0;
global lockup_notified = F;
global counter = 0; # A ping counter.

# This came back to us from the target, completing a ping roundtrip.
event manager_ping(ctr: count)
	{
	last_ping_rx = current_time();
	}

event driver() {
	Cluster::publish(ping_topic, manager_ping, ++counter);

	local now = current_time();

	if ( time_to_double(last_ping_rx) > 0.0 )
		{
		print trace_file, fmt("%s %s", now, now - last_ping_rx);

		# Trigger purely based on delay, not on counter value, since the
		# startup phase isn't coordinated and initial pings may simply
		# have gotten lost.
		if ( now - last_ping_rx > max_ping_delay && ! lockup_notified )
			{
			print fmt("%s LOCKUP", current_time());
			lockup_notified = T;
			}
		}

	schedule ping_ival { driver() };
}

event zeek_init() {
	schedule ping_ival { driver() };
}
