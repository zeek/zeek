# @TEST-DOC: Test basic parsing of IGMP traffic
#
# @TEST-EXEC: zeek -r $TRACES/igmp/igmp.pcap
# @TEST-EXEC: btest-diff igmp.log
