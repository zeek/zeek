# @TEST-DOC: Test basic parsing of IGMP v1 traffic
#
# @TEST-EXEC: zeek -r $TRACES/igmp/multicast-igmp-version-membership-query-and-report.pcap
# @TEST-EXEC: btest-diff igmp.log
