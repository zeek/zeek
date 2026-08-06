# @TEST-DOC: Ensures enabling udp-contents and reading the contents doesn't extend beyond the buffer
#
# @TEST-EXEC: zeek -br $TRACES/udp-contents-truncated-oob.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

redef udp_content_deliver_all_orig = T;

event udp_contents(u: connection, ir_orig: bool, contents: string)
	{
	print fmt("UDP contents len=%d", |contents|);
	}
