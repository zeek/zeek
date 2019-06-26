# @TEST-EXEC: zeek -b -s tcp -r $TRACES/chksums/ip4-tcp-good-chksum.pcap %INPUT >tcp_in_ip4.out
# @TEST-EXEC: zeek -b -s udp -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT >udp_in_ip4.out
# @TEST-EXEC: zeek -b -s icmp -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT >icmp_in_ip4.out
# @TEST-EXEC: zeek -b -s tcp -r $TRACES/chksums/ip6-tcp-good-chksum.pcap %INPUT >tcp_in_ip6.out
# @TEST-EXEC: zeek -b -s udp -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT >udp_in_ip6.out
# @TEST-EXEC: zeek -b -s icmp6 -r $TRACES/chksums/ip6-icmp6-good-chksum.pcap %INPUT >icmp6_in_ip6.out
# @TEST-EXEC: zeek -b -s icmp -r $TRACES/chksums/ip6-icmp6-good-chksum.pcap %INPUT >nomatch.out

# @TEST-EXEC: btest-diff tcp_in_ip4.out
# @TEST-EXEC: btest-diff udp_in_ip4.out
# @TEST-EXEC: btest-diff icmp_in_ip4.out
# @TEST-EXEC: btest-diff tcp_in_ip6.out
# @TEST-EXEC: btest-diff udp_in_ip6.out
# @TEST-EXEC: btest-diff icmp6_in_ip6.out
# @TEST-EXEC: btest-diff nomatch.out

@TEST-START-FILE tcp.sig
signature tcp_transport {
  ip-proto == tcp
  event "tcp"
}
@TEST-END-FILE

@TEST-START-FILE udp.sig
signature udp_transport {
  ip-proto == udp
  event "udp"
}
@TEST-END-FILE

@TEST-START-FILE icmp.sig
signature icmp_transport {
  ip-proto == icmp
  event "icmp"
}
@TEST-END-FILE

@TEST-START-FILE icmp6.sig
signature icmp6_transport {
  ip-proto == icmp6
  event "icmp6"
}
@TEST-END-FILE

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}
