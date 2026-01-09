##! Implements base functionality for IGMP analysis.

module IGMP;

@load base/frameworks/logging

export {
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The record type which contains the column fields of the IGMP log.
	type Info: record {
		## Timestamp
		timestamp: time &log;
		## Source IP address
		src_addr:  addr &log;
		## Destination IP address
		dst_addr:  addr &log;
		## Message type
		msg_type:  MessageType &log;
	};

	## Event that can be handled to access the IGMP record as it is sent on
	## to the logging framework.
	global log_igmp: event(rec: Info);
}

event zeek_init() &priority=5
	{
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("IP", 0x02, "IGMP") )
		{
		Reporter::error("Failed to register IGMP Spicy analyzer.");
		}

	Log::create_stream(IGMP::LOG, [$columns=Info, $ev=log_igmp, $path="igmp", $policy=log_policy]);
	}

event igmp::message(pkt_hdr: raw_pkt_hdr, msg_type: IGMP::MessageType) &priority=-5
	{
	Log::write(IGMP::LOG, Info(
		$timestamp = network_time(),
		$src_addr  = pkt_hdr$ip$src,
		$dst_addr  = pkt_hdr$ip$dst,
		$msg_type  = msg_type));
	}
