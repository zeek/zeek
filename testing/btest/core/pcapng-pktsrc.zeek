# @TEST-DOC: Tests the pcapng packet source, including sending events
#
# @TEST-EXEC: zeek -r $TRACES/pcapng-multi-interface.pcapng %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff conn.log

redef Pcapng::send_events_from_pktsrc = T;

@load base/protocols/conn

export {
	redef record Conn::Info += {
		pcapng_interface: string &optional &log;
	};
}

event pcapng_new_interface(interface: Pcapng::Interface) {
	print "pcapng_new_interface", interface;
}

## Generated when a section header block is found in a pcapng file. This contains various
## fields about the file.
##
## info: A record containing the fields from the section header block.
event pcapng_file_info(info: Pcapng::FileInfo) {
	print "pcapng_file_info", info;
}

## Generated when a packet contains optional metadata.
##
## ts: The timestamp of the packet
##
## options: A record containing the optional metadata fields from the packet.
event pcapng_packet_options(ts: time, options: Pcapng::PacketOptions) {
	print "pcap_packet_options", ts, options;
}

event new_connection(c: connection) &priority=5 {
	c$conn$pcapng_interface = pcapng_current_interface_name();
}
