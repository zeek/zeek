# @TEST-DOC: Test set_contents_file() with a truncated TCP trace.
#
# @TEST-EXEC: zeek -b -r $TRACES/tcp/tcp-truncated-contents-oob-read.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid orig_pkts resp_pkts history conn_state conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log
# @TEST-EXEC: btest-diff --binary contents.txt

@load base/protocols/conn
@load base/frameworks/notice/weird

redef dpd_reassemble_first_packets = F;

event new_connection(c: connection)
	{
	local f = open("contents.txt");
	set_contents_file(c$id, CONTENTS_BOTH, f);
	}
