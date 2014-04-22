##! Discover cases where the local interface is sniffed and outbound packets
##! have checksum offloading.  Load this script to receive a notice if it's
##! likely that checksum offload effects are being seen on a live interface or
##! in a packet trace file.

@load base/frameworks/notice

module ChecksumOffloading;

export {
	## The interval which is used for checking packet statistics
	## to see if checksum offloading is affecting analysis.
	const check_interval = 10secs &redef;
}

# Keep track of how many bad checksums have been seen.
global bad_ip_checksums  = 0;
global bad_tcp_checksums = 0;
global bad_udp_checksums = 0;

# Track to see if this script is done so that messages aren't created multiple times.
global done = F;

event ChecksumOffloading::check()
	{
	if ( done )
		return;

	local pkts_recvd = net_stats()$pkts_recvd;
	local bad_ip_checksum_pct = (pkts_recvd != 0) ? (bad_ip_checksums*1.0 / pkts_recvd*1.0) : 0;
	local bad_tcp_checksum_pct = (pkts_recvd != 0) ? (bad_tcp_checksums*1.0 / pkts_recvd*1.0) : 0;
	local bad_udp_checksum_pct = (pkts_recvd != 0) ? (bad_udp_checksums*1.0 / pkts_recvd*1.0) : 0;

	if ( bad_ip_checksum_pct  > 0.05 ||
	     bad_tcp_checksum_pct > 0.05 ||
	     bad_udp_checksum_pct > 0.05 )
		{
		local packet_src = reading_traces() ? "trace file likely has" : "interface is likely receiving";
		local bad_checksum_msg = (bad_ip_checksum_pct > 0.0) ? "IP" : "";
		if ( bad_tcp_checksum_pct > 0.0 )
			{
			if ( |bad_checksum_msg| > 0 )
				bad_checksum_msg += " and ";
			bad_checksum_msg += "TCP";
			}
		if ( bad_udp_checksum_pct > 0.0 )
			{
			if ( |bad_checksum_msg| > 0 )
				bad_checksum_msg += " and ";
			bad_checksum_msg += "UDP";
			}

		local message = fmt("Your %s invalid %s checksums, most likely from NIC checksum offloading.", packet_src, bad_checksum_msg);
		Reporter::warning(message);
		done = T;
		}
	else if ( pkts_recvd < 20 )
		{
		# Keep scheduling this event until we've seen some lower threshold of
		# total packets.
		schedule check_interval { ChecksumOffloading::check() };
		}
	}

event bro_init()
	{
	schedule check_interval { ChecksumOffloading::check() };
	}

event net_weird(name: string)
	{
	if ( name == "bad_IP_checksum" )
		++bad_ip_checksums;
	}

event conn_weird(name: string, c: connection, addl: string)
	{
	if ( name == "bad_TCP_checksum" )
		++bad_tcp_checksums;
	else if ( name == "bad_UDP_checksum" )
		++bad_udp_checksums;
	}

event bro_done()
	{
	event ChecksumOffloading::check();
	}
