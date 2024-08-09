# @TEST-DOC: Using the wrong paramters for custom signature events.
#
# @TEST-EXEC-FAIL: zeek -b -s id -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >id.out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@TEST-START-FILE id.sig
signature udp-proto {
  ip-proto == 17
  event wrong_signature2 "id"
}

signature udp-proto2 {
  ip-proto == 17
  event wrong_signature3
}

signature udp-proto3 {
  ip-proto == 17
  event wrong_signature4 "not a count"
}

signature udp-proto4 {
  ip-proto == 17
  event non_existing_event
}

signature udp-proto5 {
  ip-proto == 17
  event cat  # builtin function
}

signature udp-proto6 {
  ip-proto == 17
  event ignore_checksums  # variable
}
@TEST-END-FILE

event wrong_signature2(state: signature_state, data: string) { }

event wrong_signature3(state: signature_state, msg: string, data: string) { }

event wrong_signature4(state: signature_state, msg: count, data: string) { }
