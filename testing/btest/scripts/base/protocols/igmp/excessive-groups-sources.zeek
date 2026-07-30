# @TEST-DOC: Test that the limits for excessive groups and sources-per-group report weirds as expected.
#
# @TEST-EXEC: zeek -b -r $TRACES/igmp/igmp-many-groups.pcap %INPUT
# @TEST-EXEC: cp weird.log groups-weird.log
# @TEST-EXEC: zeek -b -r $TRACES/igmp/igmp-many-sources.pcap %INPUT
# @TEST-EXEC: cp weird.log sources-weird.log
# @TEST-EXEC: btest-diff-cut -m groups-weird.log
# @TEST-EXEC: btest-diff-cut -m sources-weird.log

@load policy/protocols/conn/multicast-participants
@load base/frameworks/notice/weird

redef Conn::max_igmp_groups = 100;
redef Conn::max_igmp_sources_per_group = 100;
