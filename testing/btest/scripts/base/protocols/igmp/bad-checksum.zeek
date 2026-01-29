# @TEST-DOC: Test parsing of IGMP traffic with bad checksums
#
# @TEST-EXEC: zeek -r $TRACES/igmp/igmp-bad-checksum.pcap %INPUT > out
# @TEST-EXEC: btest-diff igmp.log
# @TEST-EXEC: btest-diff out

event IGMP::bad_checksum(packet: raw_pkt_hdr, transmitted_checksum: count, computed_checksum: count) {
	print packet, fmt("transmitted: 0x%x   computed: 0x%x", transmitted_checksum, computed_checksum);
}
