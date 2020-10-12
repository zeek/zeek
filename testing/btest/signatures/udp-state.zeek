# @TEST-EXEC: zeek -b -s udp-states.sig -r $TRACES/dns-caa.pcap %INPUT >out
# @TEST-EXEC-FAIL: zeek -b -s udp-established.sig -r $TRACES/dns-caa.pcap %INPUT >reject 2>&1
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff reject

@TEST-START-FILE udp-states.sig
signature my_sig_udp_orig {
	ip-proto == udp
	payload /.+/
	udp-state originator
	event "my_sig_udp_orig"
}

signature my_sig_udp_resp {
	ip-proto == udp
	payload /.+/
	udp-state responder
	event "my_sig_udp_resp"
}
@TEST-END-FILE

@TEST-START-FILE udp-established.sig
signature my_sig_udp_est {
  ip-proto == udp
  payload /.+/
  udp-state established
  event "my_sig_udp_est"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	local s = split_string(hexdump(data), /\n/);
	for ( i in s ) print s[i];
	}
