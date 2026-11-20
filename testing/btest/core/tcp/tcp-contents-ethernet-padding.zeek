# @TEST-DOC: set_contents_file() must not write Ethernet padding of short TCP segments.
#
# @TEST-EXEC: zeek -b -r $TRACES/tcp/tcp-contents-ethernet-padding.pcap %INPUT
# @TEST-EXEC: btest-diff orig.txt
# @TEST-EXEC: btest-diff resp.txt

redef dpd_reassemble_first_packets = F;

event new_connection(c: connection)
	{
	set_contents_file(c$id, CONTENTS_ORIG, open("orig.txt"));
	set_contents_file(c$id, CONTENTS_RESP, open("resp.txt"));
	}
