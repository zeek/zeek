# This test validates that we can read VXLAN traffic without throwing analyzer violations
# when the internal packets are something we can't process. In this case, the internal
# packets are IGMP, which we don't have an analyzer for.

# @TEST-EXEC: zeek -r $TRACES/tunnels/vxlan-encapsulated-igmp-v2.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: ! test -f analyzer.log

@load base/frameworks/tunnels
@load base/protocols/conn
