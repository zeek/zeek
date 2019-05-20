# @TEST-EXEC: zeek -b -s ip -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >ip.out
# @TEST-EXEC: zeek -b -s ip-mask -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >ip-mask.out
# @TEST-EXEC: zeek -b -s ip6 -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >ip6.out
# @TEST-EXEC: zeek -b -s udp -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >udp.out
# @TEST-EXEC: zeek -b -s tcp -r $TRACES/chksums/ip4-tcp-good-chksum.pcap %INPUT >tcp.out
# @TEST-EXEC: zeek -b -s icmp -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT >icmp.out
# @TEST-EXEC: zeek -b -s icmp6 -r $TRACES/chksums/ip6-icmp6-good-chksum.pcap %INPUT >icmp6.out
# @TEST-EXEC: zeek -b -s val-mask -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >val-mask.out

# @TEST-EXEC: btest-diff ip.out
# @TEST-EXEC: btest-diff ip-mask.out
# @TEST-EXEC: btest-diff ip6.out
# @TEST-EXEC: btest-diff udp.out
# @TEST-EXEC: btest-diff tcp.out
# @TEST-EXEC: btest-diff icmp.out
# @TEST-EXEC: btest-diff icmp6.out
# @TEST-EXEC: btest-diff val-mask.out

@TEST-START-FILE ip.sig
signature id {
  header ip[10:1] == 0x7c
  event "ip"
}
@TEST-END-FILE

@TEST-START-FILE ip-mask.sig
signature id {
  header ip[16:4] == 127.0.0.0/24
  event "ip-mask"
}
@TEST-END-FILE

@TEST-START-FILE ip6.sig
signature id {
  header ip6[10:1] == 0x04
  event "ip6"
}
@TEST-END-FILE

@TEST-START-FILE udp.sig
signature id {
  header udp[2:1] == 0x32
  event "udp"
}
@TEST-END-FILE

@TEST-START-FILE tcp.sig
signature id {
  header tcp[3:4] == 0x50000000
  event "tcp"
}
@TEST-END-FILE

@TEST-START-FILE icmp.sig
signature id {
  header icmp[2:2] == 0xf7ff
  event "icmp"
}
@TEST-END-FILE

@TEST-START-FILE icmp6.sig
signature id {
  header icmp6[0:1] == 0x80
  event "icmp6"
}
@TEST-END-FILE

@TEST-START-FILE val-mask.sig
signature id {
  header udp[2:1] & 0x0f == 0x02
  event "val-mask"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}
