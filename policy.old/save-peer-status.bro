# $Id$
#
# Writes a summary of our peer's status into a file.

@load peer-status

event PeerStatus::update(status: PeerStatus::peer_status) &priority = -5
	{
	local f = open_log_file("peer_status");

	for ( id in PeerStatus::peers )
		{
		local stat = PeerStatus::peers[id];
		local host: string;

		if ( id != 0 )
			{
			if ( id !in Remote::connected_peers )
				next;

			host = Remote::connected_peers[id]$peer$descr;
			}
		else
			host = get_local_event_peer()$descr;

		print f, fmt("%18s %s%s %D %D %02.0f%% %4dM #%d %dK/%dK/%dK (%.1f%%)",
			host, stat$res$version, stat$res$debug ? "-DEBUG" : "",
			stat$res$start_time, stat$current_time, stat$cpu,
			stat$res$mem / 1024 / 1024,
			stat$res$num_TCP_conns + stat$res$num_UDP_conns + stat$res$num_ICMP_conns,
			stat$stats$pkts_dropped / 1024,
			stat$stats$pkts_recvd / 1024,
			stat$stats$pkts_link / 1024,
			100.0 * stat$stats$pkts_dropped / (stat$stats$pkts_dropped + stat$stats$pkts_recvd));
		}

	print f, "###";

#	for ( id in PeerStatus::peers )
#		{
#		stat = PeerStatus::peers[id];
#
#		if ( id != 0 )
#			host = Remote::connected_peers[id]$peer$descr;
#		else
#			host = get_local_event_peer()$descr;
#
#		print f, fmt("%10s %s", host, stat$default_filter);
#		print f;
#		}

	close(f);
	}
