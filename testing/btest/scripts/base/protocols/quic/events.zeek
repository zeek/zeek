# @TEST-DOC: Supported events so far.

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: echo "retry.pcap" >>out
# @TEST-EXEC: zeek -r $TRACES/quic/interop/quic-go_quic-go/retry.pcap base/protocols/quic %INPUT >>out
# @TEST-EXEC: echo "zerortt.pcap" >>out
# @TEST-EXEC: zeek -r $TRACES/quic/interop/quic-go_quic-go/zerortt.pcap base/protocols/quic %INPUT >>out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#

function b2hex(s: string):string { return bytestring_to_hexstr(s); }

event QUIC::initial_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	print network_time(), "initial_packet", c$uid, is_orig, version, b2hex(dcid), b2hex(scid);
	}

event QUIC::retry_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string, retry_token: string, integrity_tag: string)
	{
	print network_time(), "retry_packet", c$uid, is_orig, version, b2hex(dcid), b2hex(scid), |retry_token|, b2hex(integrity_tag);
	}

event QUIC::handshake_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	print network_time(), "handshake_packet", is_orig, c$uid, version, b2hex(dcid), b2hex(scid);
	}

event QUIC::zero_rtt_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	print network_time(), "zero_rtt_packet", is_orig, c$uid, version, b2hex(dcid), b2hex(scid);
	}

event QUIC::discarded_packet(c: connection, is_orig: bool, total_decrypted: count)
	{
	print network_time(), "discarded_packet", is_orig, total_decrypted;
	}

event QUIC::short_header_packet_threshold_crossed(c: connection, is_orig: bool, threshold: count)
	{
	print network_time(), "short_header_packet_threshold_crossed", is_orig, threshold;
	}
