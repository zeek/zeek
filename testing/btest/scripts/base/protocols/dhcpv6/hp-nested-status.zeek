# @TEST-DOC: Test that a STATUS_CODE nested inside an IA_NA option surfaces in dhcpv6.log.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -C -r $TRACES/dhcpv6/dhcpv6-hp24fee0.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m dhcpv6.log
# @TEST-EXEC: btest-diff-cut -m uid service history duration orig_pkts resp_pkts conn.log

@load base/protocols/conn
@load base/protocols/dhcpv6