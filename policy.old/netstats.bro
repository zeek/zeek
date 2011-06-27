# $Id: netstats.bro 564 2004-10-23 02:27:57Z vern $

@load notice

redef enum Notice += {
	DroppedPackets,	# Bro reported packets dropped by the packet filter
};

const stats_collection_interval = 10secs;

event net_stats_update(last_stat: NetStats)
	{
	local ns = net_stats();
	local new_dropped = ns$pkts_dropped - last_stat$pkts_dropped;
	if ( new_dropped > 0 )
		{
		local new_recvd = ns$pkts_recvd - last_stat$pkts_recvd;
		local new_link = ns$pkts_link - last_stat$pkts_link;
		NOTICE([$note=DroppedPackets,
			$msg=fmt("%d packets dropped after filtering, %d received%s",
				new_dropped, new_recvd + new_dropped,
				new_link != 0 ?
					fmt(", %d on link", new_link) : "")]);
		}
	
	schedule stats_collection_interval { net_stats_update(ns) };
	}

event bro_init()
	{
	schedule stats_collection_interval { net_stats_update(net_stats()) };
	}