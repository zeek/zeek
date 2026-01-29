##! Implements base functionality for IGMP analysis.

module IGMP;

@load base/frameworks/logging

export {
	redef enum Log::ID += { LOG };

	type IgmpLog: record {
		timestamp: time &log;  # Timestamp
		src_addr:  addr &log;  # Source IP address
		dst_addr:  addr &log;  # Destination IP address
		msg_type:  IgmpMessageType &log;  # Message type
	};

	## Event that can be handled to access the IGMP record as it is sent on
	## to the logging framework.
	global log_igmp: event(rec: IgmpLog);
}


########## EVENTS ##########

# Triggered when the module is loaded.
# 1. Registers the IGMP packet analyzer.
# 2. Creates the IGMP log stream.
event zeek_init() &priority=5
	{
	# Register the IGMP packet analyzer.
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("IP", 0x02, "IGMP") )
		{
		Reporter::error("Failed to register IGMP Spicy analyzer.");
		}

	# Create the IGMP log stream.
	Log::create_stream(IGMP::LOG, [$columns=IgmpLog, $ev=log_igmp, $path="igmp"]);
	}

# Triggered upon reception of any IGMP message.
# Logs the IGMP message.
# :param pkt_hdr:  raw packet header
# :param msg_type: IGMP message type
event igmp::message(pkt_hdr: raw_pkt_hdr, msg_type: IgmpMessageType) &priority=-5
	{
	Log::write(IGMP::LOG, IgmpLog(
		$timestamp = network_time(),
		$src_addr  = pkt_hdr$ip$src,
		$dst_addr  = pkt_hdr$ip$dst,
		$msg_type  = msg_type));
	}
