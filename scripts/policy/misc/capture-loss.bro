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
	
	redef enum Notice::Type += {
		## Report if the detected capture loss exceeds the percentage
		## threshold.
		Too_Much_Loss
	};
	
	type Info: record {
		## Timestamp for when the measurement occurred.
		ts:           time     &log;
		## The time delay between this measurement and the last.
		ts_delta:     interval &log;
		## In the event that there are multiple Bro instances logging
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
	
	## The interval at which capture loss reports are created.
	const watch_interval = 15mins &redef;
	
	## The percentage of missed data that is considered "too much" 
	## when the :bro:enum:`CaptureLoss::Too_Much_Loss` notice should be
	## generated. The value is expressed as a double between 0 and 1 with 1
	## being 100%.
	const too_much_loss: double = 0.1 &redef;
}

event CaptureLoss::take_measurement(last_ts: time, last_acks: count, last_gaps: count)
	{
	if ( last_ts == 0 )
		{
		schedule watch_interval { CaptureLoss::take_measurement(network_time(), 0, 0) };
		return;
		}
	
	local now = network_time();
	local g = get_gap_summary();
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
	
	Log::write(LOG, info);
	schedule watch_interval { CaptureLoss::take_measurement(now, g$ack_events, g$gap_events) };
	}

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info]);

	# We only schedule the event if we are capturing packets.
	if ( reading_live_traffic() || reading_traces() )
		schedule watch_interval { CaptureLoss::take_measurement(network_time(), 0, 0) };
	}
