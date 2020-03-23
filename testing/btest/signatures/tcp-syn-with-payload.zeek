# @TEST-EXEC: zeek -b -s payload-http.sig -r $TRACES/tcp/payload-syn.pcap %INPUT >payload-syn.out
# @TEST-EXEC: zeek -b -s payload-http.sig -r $TRACES/tcp/payload-synack.pcap %INPUT >payload-synack.out
# @TEST-EXEC: zeek -b -s payload-http.sig -r $TRACES/tcp/tcp-fast-open.pcap %INPUT >tcp-fast-open.out
# @TEST-EXEC: btest-diff payload-syn.out
# @TEST-EXEC: btest-diff payload-synack.out
# @TEST-EXEC: btest-diff tcp-fast-open.out

@TEST-START-FILE payload-http.sig
signature test-signature {
	ip-proto == tcp
	dst-port = 80
	payload /.*passwd/
	event "payload of dst-port=80/tcp contains 'passwd'"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}
