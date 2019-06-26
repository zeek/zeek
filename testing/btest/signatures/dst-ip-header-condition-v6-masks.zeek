# @TEST-EXEC: zeek -b -s dst-ip-eq -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-ip-eq.out
# @TEST-EXEC: zeek -b -s dst-ip-eq-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-ip-eq-nomatch.out
# @TEST-EXEC: zeek -b -s dst-ip-eq-list -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-ip-eq-list.out

# @TEST-EXEC: zeek -b -s dst-ip-ne -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-ip-ne.out
# @TEST-EXEC: zeek -b -s dst-ip-ne-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-ip-ne-nomatch.out
# @TEST-EXEC: zeek -b -s dst-ip-ne-list -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-ip-ne-list.out
# @TEST-EXEC: zeek -b -s dst-ip-ne-list-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-ip-ne-list-nomatch.out

# @TEST-EXEC: btest-diff dst-ip-eq.out
# @TEST-EXEC: btest-diff dst-ip-eq-nomatch.out
# @TEST-EXEC: btest-diff dst-ip-eq-list.out

# @TEST-EXEC: btest-diff dst-ip-ne.out
# @TEST-EXEC: btest-diff dst-ip-ne-nomatch.out
# @TEST-EXEC: btest-diff dst-ip-ne-list.out
# @TEST-EXEC: btest-diff dst-ip-ne-list-nomatch.out

@TEST-START-FILE dst-ip-eq.sig
signature id {
  dst-ip == [2001:4f8:4:7:2e0:81ff:fe52:0]/112
  event "dst-ip-eq"
}
@TEST-END-FILE

@TEST-START-FILE dst-ip-eq-nomatch.sig
signature id {
  dst-ip == [fe80::0]/16
  event "dst-ip-eq-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE dst-ip-eq-list.sig
signature id {
  dst-ip == 10.0.0.0/8,[fe80::0]/16,[2001:4f8:4:7:2e0:81ff:fe52:0]/112
  event "dst-ip-eq-list"
}
@TEST-END-FILE

@TEST-START-FILE dst-ip-ne.sig
signature id {
  dst-ip != [2001:4f8:4:7:2e0:81ff:fe52:0]/120
  event "dst-ip-ne"
}
@TEST-END-FILE

@TEST-START-FILE dst-ip-ne-nomatch.sig
signature id {
  dst-ip != [2001:4f8:4:7:2e0:81ff:fe52:0]/112
  event "dst-ip-ne-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE dst-ip-ne-list.sig
signature id {
  dst-ip != 10.0.0.0/8,[fe80::0]/16
  event "dst-ip-ne-list"
}
@TEST-END-FILE

@TEST-START-FILE dst-ip-ne-list-nomatch.sig
signature id {
  dst-ip != 10.0.0.0/8,[fe80::1]/16,[2001:4f8:4:7:2e0:81ff:fe52:0]/112
  event "dst-ip-ne-list-nomatch"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}
