# @TEST-DOC: Test the [event_name] notation within the event keyword of rules.
#
# @TEST-EXEC: zeek -b -s id -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# @TEST-EXEC: btest-diff out

@TEST-START-FILE id.sig
signature udp-proto {
  ip-proto == 17
  event [my_signature_match3] "message"
}

signature udp-proto-msg-id {
  ip-proto == 17
  event [my_signature_match3] message_as_id
}

signature udp-proto-msg-id2 {
  ip-proto == 17
  event message_as_id
}

signature udp-stuff {
  dst-ip == mynets
  event [my_signature_match2]
}

@TEST-END-FILE

const message_as_id = "message from identifier (cannot be changed)";

const mynets: set[subnet] = {
	192.168.1.0/24,
	10.0.0.0/8,
	127.0.0.0/24
};

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}

event my_signature_match2(state: signature_state, data: string)
	{
	print fmt("signature_match2 %s", state$conn$id);
	}

event my_signature_match3(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match3 %s - %s", state$conn$id, msg);
	}
