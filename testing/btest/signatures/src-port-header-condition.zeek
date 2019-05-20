# @TEST-EXEC: zeek -b -s src-port-eq -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >src-port-eq.out
# @TEST-EXEC: zeek -b -s src-port-eq-nomatch -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >src-port-eq-nomatch.out
# @TEST-EXEC: zeek -b -s src-port-eq-list -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >src-port-eq-list.out
# @TEST-EXEC: zeek -b -s src-port-eq -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-eq-ip6.out

# @TEST-EXEC: zeek -b -s src-port-ne -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-ne.out
# @TEST-EXEC: zeek -b -s src-port-ne-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-ne-nomatch.out
# @TEST-EXEC: zeek -b -s src-port-ne-list -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-ne-list.out
# @TEST-EXEC: zeek -b -s src-port-ne-list-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-ne-list-nomatch.out

# @TEST-EXEC: zeek -b -s src-port-lt -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-lt.out
# @TEST-EXEC: zeek -b -s src-port-lt-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-lt-nomatch.out
# @TEST-EXEC: zeek -b -s src-port-lte1 -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-lte1.out
# @TEST-EXEC: zeek -b -s src-port-lte2 -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-lte2.out
# @TEST-EXEC: zeek -b -s src-port-lte-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-lte-nomatch.out

# @TEST-EXEC: zeek -b -s src-port-gt -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-gt.out
# @TEST-EXEC: zeek -b -s src-port-gt-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-gt-nomatch.out
# @TEST-EXEC: zeek -b -s src-port-gte1 -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-gte1.out
# @TEST-EXEC: zeek -b -s src-port-gte2 -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-gte2.out
# @TEST-EXEC: zeek -b -s src-port-gte-nomatch -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >src-port-gte-nomatch.out

# @TEST-EXEC: btest-diff src-port-eq.out
# @TEST-EXEC: btest-diff src-port-eq-nomatch.out
# @TEST-EXEC: btest-diff src-port-eq-list.out
# @TEST-EXEC: btest-diff src-port-eq-ip6.out
# @TEST-EXEC: btest-diff src-port-ne.out
# @TEST-EXEC: btest-diff src-port-ne-nomatch.out
# @TEST-EXEC: btest-diff src-port-ne-list.out
# @TEST-EXEC: btest-diff src-port-ne-list-nomatch.out
# @TEST-EXEC: btest-diff src-port-lt.out
# @TEST-EXEC: btest-diff src-port-lt-nomatch.out
# @TEST-EXEC: btest-diff src-port-lte1.out
# @TEST-EXEC: btest-diff src-port-lte2.out
# @TEST-EXEC: btest-diff src-port-lte-nomatch.out
# @TEST-EXEC: btest-diff src-port-gt.out
# @TEST-EXEC: btest-diff src-port-gt-nomatch.out
# @TEST-EXEC: btest-diff src-port-gte1.out
# @TEST-EXEC: btest-diff src-port-gte2.out
# @TEST-EXEC: btest-diff src-port-gte-nomatch.out

@TEST-START-FILE src-port-eq.sig
signature id {
  src-port == 30000
  event "src-port-eq"
}
@TEST-END-FILE

@TEST-START-FILE src-port-eq-nomatch.sig
signature id {
  src-port == 22
  event "src-port-eq-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE src-port-eq-list.sig
signature id {
  src-port == 22,23,24,30000
  event "src-port-eq-list"
}
@TEST-END-FILE

@TEST-START-FILE src-port-ne.sig
signature id {
  src-port != 22
  event "src-port-ne"
}
@TEST-END-FILE

@TEST-START-FILE src-port-ne-nomatch.sig
signature id {
  src-port != 30000
  event "src-port-ne-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE src-port-ne-list.sig
signature id {
  src-port != 22,23,24,25
  event "src-port-ne-list"
}
@TEST-END-FILE

@TEST-START-FILE src-port-ne-list-nomatch.sig
signature id {
  src-port != 22,23,24,25,30000
  event "src-port-ne-list-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE src-port-lt.sig
signature id {
  src-port < 30001
  event "src-port-lt"
}
@TEST-END-FILE

@TEST-START-FILE src-port-lt-nomatch.sig
signature id {
  src-port < 30000
  event "src-port-lt-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE src-port-lte1.sig
signature id {
  src-port <= 30000
  event "src-port-lte1"
}
@TEST-END-FILE

@TEST-START-FILE src-port-lte2.sig
signature id {
  src-port <= 30001
  event "src-port-lte2"
}
@TEST-END-FILE

@TEST-START-FILE src-port-lte-nomatch.sig
signature id {
  src-port <= 29999
  event "src-port-lte-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE src-port-gt.sig
signature id {
  src-port > 29999
  event "src-port-gt"
}
@TEST-END-FILE

@TEST-START-FILE src-port-gt-nomatch.sig
signature id {
  src-port > 30000
  event "src-port-gt-nomatch"
}
@TEST-END-FILE

@TEST-START-FILE src-port-gte1.sig
signature id {
  src-port >= 30000
  event "src-port-gte1"
}
@TEST-END-FILE

@TEST-START-FILE src-port-gte2.sig
signature id {
  src-port >= 29999
  event "src-port-gte2"
}
@TEST-END-FILE

@TEST-START-FILE src-port-gte-nomatch.sig
signature id {
  src-port >= 30001
  event "src-port-gte-nomatch"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}
