##! This script reports on packet loss from the various packet sources.
##! The time between packet loss reporting intervals can be configured
##! with the :bro:id:`heartbeat_interval` variable.

@load notice

module PacketFilter;

export {
	redef enum Notice::Type += {
		## Bro reported packets dropped by the packet filter.
		DroppedPackets,
	};
}

global last_stat: net_stats;
global have_stats = F;

event net_stats_update(t: time, ns: net_stats)
	{
	if ( have_stats )
		{
		local new_dropped = ns$pkts_dropped - last_stat$pkts_dropped;
		if ( new_dropped > 0 )
			{
			local new_recvd = ns$pkts_recvd - last_stat$pkts_recvd;
			local new_link = ns$pkts_link - last_stat$pkts_link;
			NOTICE([$note=DroppedPackets,
			        $msg=fmt("%d packets dropped after filtering, %d received%s",
			                 new_dropped, new_recvd + new_dropped,
			                 new_link != 0 ? fmt(", %d on link", new_link) : "")]);
			}
		}
	else
		have_stats = T;

	last_stat = ns;
	}
