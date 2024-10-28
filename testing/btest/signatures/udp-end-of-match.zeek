# @TEST-DOC: Check optional data_end_offset parameter for signature_match()
# @TEST-EXEC: zeek -b -r $TRACES/dns-caa.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr

@load-sigs ./test.sig

event signature_match(state: signature_state, msg: string, data: string, data_end_offset: count)
	{
	print fmt("signature_match %s - %s - offset=%s", state$conn$id, msg, data_end_offset);
	local s = split_string(hexdump(data[:data_end_offset]), /\n/);
	for ( i in s ) print s[i];
	}

@TEST-START-FILE test.sig
signature my_sig_udp_orig {
	ip-proto == udp
	payload /.+google/
	udp-state originator
	event "my_sig_udp_orig"
}
@TEST-END-FILE
