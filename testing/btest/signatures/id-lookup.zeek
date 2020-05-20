# @TEST-EXEC: zeek -b -s id -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >id.out
# @TEST-EXEC: btest-diff id.out

@TEST-START-FILE id.sig
signature id {
  ip-proto == udp_proto_number
  event "id"
}

signature idtable {
  dst-ip == mynets
  event "idtable"
}
@TEST-END-FILE

const udp_proto_number = 17;

const mynets: set[subnet] = {
	192.168.1.0/24,
	10.0.0.0/8,
	127.0.0.0/24
};

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}
