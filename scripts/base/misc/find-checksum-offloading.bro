##! Discover cases where the local interface was sniffed and outbound packets
##! had checksum offloading.  Load this script to receive a notice if it's 
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
global bad_checksums = 0;
# Track to see if this script is done so that messages aren't created multiple times.
global done = F;


event ChecksumOffloading::check()
	{
	if ( done ) 
		return;
	
	local pkts_recvd = net_stats()$pkts_recvd;
	if ( (bad_checksums*1.0 / net_stats()$pkts_recvd*1.0) > 0.05 )
		{
		local packet_src = reading_traces() ? "trace file likely has" : "interface is likely receiving";
		local message = fmt("Your %s invalid IP checksums, most likely from NIC checksum offloading.", packet_src);
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
		++bad_checksums;
	}

event bro_done()
	{
	event ChecksumOffloading::check();
	}