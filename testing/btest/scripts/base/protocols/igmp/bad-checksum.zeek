# @TEST-DOC: Test parsing of IGMP traffic with bad checksums
#
# @TEST-EXEC: zeek -r $TRACES/igmp/igmp-bad-checksum.pcap %INPUT
# @TEST-EXEC: btest-diff igmp.log
# @TEST-EXEC: btest-diff weird.log

@load base/frameworks/notice/weird
