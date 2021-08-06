# @TEST-DOC: Use Config::set_value() to clear ignore_checksums_nets after having received a few packets. Expect a bad_TCP_checksum weird.log entry due to the following packets.
# @TEST-EXEC: zeek -b -r $TRACES/chksums/localhost-bad-chksum.pcap "ignore_checksums_nets += {192.168.0.0/16}" %INPUT
# @TEST-EXEC: btest-diff weird.log

@load base/frameworks/config
@load base/frameworks/notice

global packet_counter = 0;

event new_packet(c: connection, p: pkt_hdr)
	{
	++packet_counter;
	if ( packet_counter > 3 )
		{
		local s: set[subnet] = set();
		Config::set_value("ignore_checksums_nets", s);
		}
	}
