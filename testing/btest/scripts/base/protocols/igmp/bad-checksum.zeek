# @TEST-DOC: Test parsing of IGMP traffic with bad checksums
#
# @TEST-EXEC: zeek -r $TRACES/igmp/igmp-bad-checksum.pcap
# @TEST-EXEC: btest-diff igmp.log
