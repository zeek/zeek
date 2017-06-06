##! This script reports on packet loss from the various packet sources.
##! When Bro is reading input from trace files, this script will not
##! report any packet loss statistics.

@load base/frameworks/notice

module PacketFilter;

export {
	redef enum Notice::Type += {
		## Indicates packets were dropped by the packet filter.
		Dropped_Packets,
	};

	## This is the interval between individual statistics collection.
	const stats_collection_interval = 5min;

	# Add in variable to disable log writing - this saves a lot of notice.log spam
	const write_dropped_packets_notice_logs: bool = T &redef;
}

event net_stats_update(last_stat: NetStats)
	{
	local ns = get_net_stats();
	local new_dropped = ns$pkts_dropped - last_stat$pkts_dropped;
	if (write_dropped_packets_notice_logs == T ) {
		if ( new_dropped > 0 )
			{
			local new_recvd = ns$pkts_recvd - last_stat$pkts_recvd;
			local new_link = ns$pkts_link - last_stat$pkts_link;
			NOTICE([$note=Dropped_Packets,
		        	$msg=fmt("%d packets dropped after filtering, %d received%s",
		                 	new_dropped, new_recvd + new_dropped,
		                 	new_link != 0 ? fmt(", %d on link", new_link) : "")]);
		}
	}

	schedule stats_collection_interval { net_stats_update(ns) };
	}

event bro_init()
	{
	# Since this currently only calculates packet drops, let's skip the stats
	# collection if reading traces.
	if ( ! reading_traces() )
		schedule stats_collection_interval { net_stats_update(get_net_stats()) };
	}
