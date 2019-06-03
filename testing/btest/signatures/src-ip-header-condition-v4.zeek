# @TEST-EXEC: zeek -b -s src-ip-eq -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT >src-ip-eq.out
# @TEST-EXEC: zeek -b -s src-ip-eq-nomatch -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT >src-ip-eq-nomatch.out
# @TEST-EXEC: zeek -b -s src-ip-eq-list -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT >src-ip-eq-list.out

# @TEST-EXEC: zeek -b -s src-ip-ne -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT >src-ip-ne.out
# @TEST-EXEC: zeek -b -s src-ip-ne-nomatch -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT >src-ip-ne-nomatch.out
# @TEST-EXEC: zeek -b -s src-ip-ne-list -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT >src-ip-ne-list.out
# @TEST-EXEC: zeek -b -s src-ip-ne-list-nomatch -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT >src-ip-ne-list-nomatch.out

# @TEST-EXEC: btest-diff src-ip-eq.out
# @TEST-EXEC: btest-diff src-ip-eq-nomatch.out
# @TEST-EXEC: btest-diff src-ip-eq-list.out

# @TEST-EXEC: btest-diff src-ip-ne.out
# @TEST-EXEC: btest-diff src-ip-ne-nomatch.out
# @TEST-EXEC: btest-diff src-ip-ne-list.out
# @TEST-EXEC: btest-diff src-ip-ne-list-nomatch.out

@TEST-START-FILE src-ip-eq.sig
signature id {
  src-ip == 192.168.1.100
  event "src-ip-eq"
}
@TEST-END-FILE

@TEST-START-FILE src-ip-eq-nomatch.sig
signature id {
  src-ip == 10.0.0.1
  event "src-ip-eq-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE src-ip-eq-list.sig
signature id {
  src-ip == 10.0.0.1,10.0.0.2,[fe80::1],192.168.1.100
  event "src-ip-eq-list"
}
@TEST-END-FILE

@TEST-START-FILE src-ip-ne.sig
signature id {
  src-ip != 10.0.0.1
  event "src-ip-ne"
}
@TEST-END-FILE

@TEST-START-FILE src-ip-ne-nomatch.sig
signature id {
  src-ip != 192.168.1.100
  event "src-ip-ne-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE src-ip-ne-list.sig
signature id {
  src-ip != 10.0.0.1,10.0.0.2,10.0.0.3,[fe80::1]
  event "src-ip-ne-list"
}
@TEST-END-FILE

@TEST-START-FILE src-ip-ne-list-nomatch.sig
signature id {
  src-ip != 10.0.0.1,10.0.0.2,10.0.0.3,[fe80::1],192.168.1.100
  event "src-ip-ne-list-nomatch"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}
