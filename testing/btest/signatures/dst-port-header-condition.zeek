# @TEST-EXEC: zeek -b -s dst-port-eq -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >dst-port-eq.out
# @TEST-EXEC: zeek -b -s dst-port-eq-nomatch -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >dst-port-eq-nomatch.out
# @TEST-EXEC: zeek -b -s dst-port-eq-list -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >dst-port-eq-list.out
# @TEST-EXEC: zeek -b -s dst-port-eq -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-eq-ip6.out

# @TEST-EXEC: zeek -b -s dst-port-ne -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-ne.out
# @TEST-EXEC: zeek -b -s dst-port-ne-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-ne-nomatch.out
# @TEST-EXEC: zeek -b -s dst-port-ne-list -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-ne-list.out
# @TEST-EXEC: zeek -b -s dst-port-ne-list-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-ne-list-nomatch.out

# @TEST-EXEC: zeek -b -s dst-port-lt -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-lt.out
# @TEST-EXEC: zeek -b -s dst-port-lt-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-lt-nomatch.out
# @TEST-EXEC: zeek -b -s dst-port-lte1 -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-lte1.out
# @TEST-EXEC: zeek -b -s dst-port-lte2 -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-lte2.out
# @TEST-EXEC: zeek -b -s dst-port-lte-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-lte-nomatch.out

# @TEST-EXEC: zeek -b -s dst-port-gt -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-gt.out
# @TEST-EXEC: zeek -b -s dst-port-gt-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-gt-nomatch.out
# @TEST-EXEC: zeek -b -s dst-port-gte1 -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-gte1.out
# @TEST-EXEC: zeek -b -s dst-port-gte2 -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-gte2.out
# @TEST-EXEC: zeek -b -s dst-port-gte-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >dst-port-gte-nomatch.out

# @TEST-EXEC: btest-diff dst-port-eq.out
# @TEST-EXEC: btest-diff dst-port-eq-nomatch.out
# @TEST-EXEC: btest-diff dst-port-eq-list.out
# @TEST-EXEC: btest-diff dst-port-eq-ip6.out
# @TEST-EXEC: btest-diff dst-port-ne.out
# @TEST-EXEC: btest-diff dst-port-ne-nomatch.out
# @TEST-EXEC: btest-diff dst-port-ne-list.out
# @TEST-EXEC: btest-diff dst-port-ne-list-nomatch.out
# @TEST-EXEC: btest-diff dst-port-lt.out
# @TEST-EXEC: btest-diff dst-port-lt-nomatch.out
# @TEST-EXEC: btest-diff dst-port-lte1.out
# @TEST-EXEC: btest-diff dst-port-lte2.out
# @TEST-EXEC: btest-diff dst-port-lte-nomatch.out
# @TEST-EXEC: btest-diff dst-port-gt.out
# @TEST-EXEC: btest-diff dst-port-gt-nomatch.out
# @TEST-EXEC: btest-diff dst-port-gte1.out
# @TEST-EXEC: btest-diff dst-port-gte2.out
# @TEST-EXEC: btest-diff dst-port-gte-nomatch.out

@TEST-START-FILE dst-port-eq.sig
signature id {
  dst-port == 13000
  event "dst-port-eq"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-eq-nomatch.sig
signature id {
  dst-port == 22
  event "dst-port-eq-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-eq-list.sig
signature id {
  dst-port == 22,23,24,13000
  event "dst-port-eq-list"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-ne.sig
signature id {
  dst-port != 22
  event "dst-port-ne"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-ne-nomatch.sig
signature id {
  dst-port != 13000
  event "dst-port-ne-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-ne-list.sig
signature id {
  dst-port != 22,23,24,25
  event "dst-port-ne-list"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-ne-list-nomatch.sig
signature id {
  dst-port != 22,23,24,25,13000
  event "dst-port-ne-list-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-lt.sig
signature id {
  dst-port < 13001
  event "dst-port-lt"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-lt-nomatch.sig
signature id {
  dst-port < 13000
  event "dst-port-lt-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-lte1.sig
signature id {
  dst-port <= 13000
  event "dst-port-lte1"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-lte2.sig
signature id {
  dst-port <= 13001
  event "dst-port-lte2"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-lte-nomatch.sig
signature id {
  dst-port <= 12999
  event "dst-port-lte-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-gt.sig
signature id {
  dst-port > 12999
  event "dst-port-gt"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-gt-nomatch.sig
signature id {
  dst-port > 13000
  event "dst-port-gt-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-gte1.sig
signature id {
  dst-port >= 13000
  event "dst-port-gte1"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-gte2.sig
signature id {
  dst-port >= 12999
  event "dst-port-gte2"
}
@TEST-END-FILE

@TEST-START-FILE dst-port-gte-nomatch.sig
signature id {
  dst-port >= 13001
  event "dst-port-gte-nomatch"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}
