# @TEST-EXEC: bro -b -s id -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >id.out
# @TEST-EXEC: btest-diff id.out

@TEST-START-FILE id.sig
signature id {
  ip-proto == udp_proto_number
  event "id"
}
@TEST-END-FILE

const udp_proto_number = 17;

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}
