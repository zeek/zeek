# @TEST-DOC: The DCE-RPC DPD signature only matches over TCP, so a UDP payload that starts like a DCE-RPC header does not enable the TCP-only DCE_RPC analyzer.
#
# DCE-RPC over TCP on 4997/tcp matches the signature, and the analyzer it enables confirms the service.
# @TEST-EXEC: zeek -b -s dce-rpc-matched.sig -DCr $TRACES/dce-rpc/ntlm-empty-av-sequence.pcap %INPUT >tcp.out
# @TEST-EXEC: btest-diff tcp.out
# @TEST-EXEC: mv conn.log tcp-conn.log
# @TEST-EXEC: btest-diff-cut -m uid service history tcp-conn.log
#
# A DNS query with bytes 05 00 01 matches the signature, but over UDP the signature must not match.
# @TEST-EXEC: zeek -b -s dce-rpc-matched.sig -DCr $TRACES/dce-rpc/dns-id-0x0500-over-udp.pcap %INPUT >udp.out
# @TEST-EXEC: btest-diff udp.out
# @TEST-EXEC: mv conn.log udp-conn.log
# @TEST-EXEC: btest-diff-cut -m uid service history udp-conn.log

@load base/protocols/conn
@load base/protocols/dce-rpc

event signature_match(state: signature_state, msg: string, data: string)
	{
	print "signature_match", state$conn$id$resp_p, state$sig_id, msg;
	}

# @TEST-START-FILE dce-rpc-matched.sig
signature dpd_dce_rpc_matched {
	requires-signature dpd_dce_rpc
	event "dpd_dce_rpc matched"
}
# @TEST-END-FILE
