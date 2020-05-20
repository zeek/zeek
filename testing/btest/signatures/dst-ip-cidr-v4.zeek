# @TEST-EXEC: zeek -r $TRACES/ntp.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE a.sig
signature foo {
    dst-ip == 17.0.0.0/8
    ip-proto == udp
    event "match"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print "match", state$sig_id;
	}

@load-sigs ./a.sig
