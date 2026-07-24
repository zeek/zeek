# @TEST-DOC: Tests that tunneled ARP behaves correctly
#
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/geneve-arp.pcap %INPUT > out
# @TEST-EXEC: btest-diff-cut -m conn.log
# @TEST-EXEC: btest-diff out

@load base/protocols/conn

event bad_arp(SPA: addr, SHA: string, TPA: addr, THA: string, explanation: string)
	{
	print "bad_arp", SPA, SHA, explanation;
	}
