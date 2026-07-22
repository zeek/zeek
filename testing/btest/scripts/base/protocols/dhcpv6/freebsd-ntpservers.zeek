# @TEST-DOC: Test that DHCPv6 is logged into dhcpv6.log.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b -C -r $TRACES/dhcpv6/dhcpv6-freebsd-ntpservers.pcap %INPUT
# @TEST-EXEC: btest-diff dhcpv6.log

@load base/protocols/dhcpv6
