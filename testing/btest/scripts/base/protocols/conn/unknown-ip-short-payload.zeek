# @TEST-DOC: Test that packet_contents works with unknown IP protocols that have short payloads (< 8 bytes)
# @TEST-EXEC: zeek -b -r $TRACES/unknown-ip-short-payload.pcap %INPUT > output 2>&1
# @TEST-EXEC: btest-diff output

event packet_contents(c: connection, contents: string)
	{
	print fmt("packet_contents: |%s| len=%d", c$id, |contents|);
	}
