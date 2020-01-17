# In the pcaps used here, the first encrypted packet is sent along with NEWKEYS
# message of either the client (1st pcap) or the server (2nd pcap) instead of
# separately.  The "ssh_encrypted_packet" should be raised for such encrypted
# data appearing within the same tcp segment delivery as other non-encrypted
# messages.

# @TEST-EXEC: zeek -b -C -r $TRACES/ssh/ssh_client_sends_first_enc_pkt_with_newkeys.pcap %INPUT > client.out
# @TEST-EXEC: zeek -b -C -r $TRACES/ssh/ssh_server_sends_first_enc_pkt_with_newkeys.pcap %INPUT > server.out
# @TEST-EXEC: btest-diff client.out
# @TEST-EXEC: btest-diff server.out

@load base/protocols/ssh

global pkts: count = 0;
redef SSH::disable_analyzer_after_detection = F;

event ssh_encrypted_packet(c: connection, orig: bool, len: count)
	{
	print pkts, orig, len;
	++pkts;
	}
