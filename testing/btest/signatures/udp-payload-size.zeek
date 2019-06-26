# @TEST-EXEC: zeek -r $TRACES/ntp.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE a.sig
signature foo1 {
    ip-proto == udp
    payload-size < 1
    event "match"
}

signature foo2 {
    ip-proto == udp
    payload-size > 0
    event "match"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print "match", state$sig_id;
	}

@load-sigs ./a.sig
