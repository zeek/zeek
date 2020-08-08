# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-bad-chksum.pcap %INPUT
# @TEST-EXEC: mv weird.log bad.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-tcp-bad-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> bad.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-udp-bad-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> bad.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-icmp-bad-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> bad.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-route0-tcp-bad-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> bad.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-route0-udp-bad-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> bad.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-route0-icmp6-bad-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> bad.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-tcp-bad-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> bad.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-udp-bad-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> bad.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-icmp6-bad-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> bad.out

# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-tcp-good-chksum.pcap %INPUT
# @TEST-EXEC: mv weird.log good.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-udp-good-chksum.pcap %INPUT
# @TEST-EXEC: test ! -e weird.log
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-icmp-good-chksum.pcap %INPUT
# @TEST-EXEC: test ! -e weird.log
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-route0-tcp-good-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> good.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-route0-udp-good-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> good.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-route0-icmp6-good-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> good.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-tcp-good-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> good.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-udp-good-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> good.out
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-icmp6-good-chksum.pcap %INPUT
# @TEST-EXEC: cat weird.log >> good.out

# @TEST-EXEC: btest-diff bad.out
# @TEST-EXEC: btest-diff good.out

@load base/frameworks/notice/weird
