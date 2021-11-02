# @TEST-REQUIRES: which hexdump
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: hexdump -C 1.pcap >1.hex
# @TEST-EXEC: hexdump -C 2.pcap >2.hex
# @TEST-EXEC: btest-diff 1.hex
# @TEST-EXEC: btest-diff 2.hex

# Run the same test a second time, which will try to write to an
# existing file and shouldn't crash a sanitizer build.
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT

# Note that the hex output will contain global pcap header information,
# including Zeek's snaplen setting (so maybe check that out in the case
# you are reading this message due to this test failing in the future).

global i: count = 0;

event new_packet(c: connection, p: pkt_hdr)
	{
	++i;
	dump_current_packet(cat(i, ".pcap"));
	if ( i >= 3 )
		terminate();
	}
