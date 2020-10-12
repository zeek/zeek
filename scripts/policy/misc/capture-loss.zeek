##! This script logs evidence regarding the degree to which the packet
##! capture process suffers from measurement loss.
##! The loss could be due to overload on the host or NIC performing
##! the packet capture or it could even be beyond the host.  If you are
##! capturing from a switch with a SPAN port, it's very possible that
##! the switch itself could be overloaded and dropping packets.
##! Reported loss is computed in terms of the number of "gap events" (ACKs
##! for a sequence number that's above a gap).

@load base/frameworks/notice

module CaptureLoss;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	redef enum Notice::Type += {
		## Report if the detected capture loss exceeds the percentage
		## threshold defined in :zeek:id:`CaptureLoss::too_much_loss`.
		Too_Much_Loss,
		## Report if the traffic seen by a peer within a given watch
		## interval is less than :zeek:id:`CaptureLoss::minimum_acks`.
		Too_Little_Traffic,
	};

	type Info: record {
		## Timestamp for when the measurement occurred.
		ts:           time     &log;
		## The time delay between this measurement and the last.
		ts_delta:     interval &log;
		## In the event that there are multiple Zeek instances logging
		## to the same host, this distinguishes each peer with its
		## individual name.
		peer:         string   &log;
		## Number of missed ACKs from the previous measurement interval.
		gaps:         count    &log;
		## Total number of ACKs seen in the previous measurement interval.
		acks:         count    &log;
		## Percentage of ACKs seen where the data being ACKed wasn't seen.
		percent_lost: double   &log;
	};

	## The interval at which capture loss reports are created in a
	## running cluster (that is, after the first report).
	option watch_interval = 15mins;

	## For faster feedback on cluster health, the first capture loss
	## report is generated this many minutes after startup.
	option initial_watch_interval = 1mins;

	## The percentage of missed data that is considered "too much"
	## when the :zeek:enum:`CaptureLoss::Too_Much_Loss` notice should be
	## generated. The value is expressed as a double between 0 and 1 with 1
	## being 100%.
	option too_much_loss: double = 0.1;

	## The minimum number of ACKs expected for a single peer in a
	## watch interval. If the number seen is less than this,
	## :zeek:enum:`CaptureLoss::Too_Little_Traffic` is raised.
	option minimum_acks: count = 1;
}

event CaptureLoss::take_measurement(last_ts: time, last_acks: count, last_gaps: count)
	{
	if ( last_ts == 0 )
		{
		schedule initial_watch_interval { CaptureLoss::take_measurement(network_time(), 0, 0) };
		return;
		}

	local now = network_time();
	local g = get_gap_stats();
	local acks = g$ack_events - last_acks;
	local gaps = g$gap_events - last_gaps;
	local pct_lost = (acks == 0) ? 0.0 : (100 * (1.0 * gaps) / (1.0 * acks));
	local info: Info = [$ts=now,
	                    $ts_delta=now-last_ts,
	                    $peer=peer_description,
	                    $acks=acks, $gaps=gaps,
	                    $percent_lost=pct_lost];

	if ( pct_lost >= too_much_loss*100 )
		NOTICE([$note=Too_Much_Loss,
		        $msg=fmt("The capture loss script detected an estimated loss rate above %.3f%%", pct_lost)]);

	if ( acks < minimum_acks )
		NOTICE([$note=Too_Little_Traffic,
		        $msg=fmt("Only observed %d TCP ACKs and was expecting at least %d.", acks, minimum_acks)]);

	Log::write(LOG, info);
	schedule watch_interval { CaptureLoss::take_measurement(now, g$ack_events, g$gap_events) };
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $path="capture_loss", $policy=log_policy]);

	# We only schedule the event if we are capturing packets.
	if ( reading_live_traffic() || reading_traces() )
		schedule initial_watch_interval { CaptureLoss::take_measurement(network_time(), 0, 0) };
	}
