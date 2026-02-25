# @TEST-DOC: Verify triple-tagged QinQinQ traffic produces a weird
#
# @TEST-EXEC: zeek -br $TRACES/vlan-qinqinq.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/frameworks/notice/weird
