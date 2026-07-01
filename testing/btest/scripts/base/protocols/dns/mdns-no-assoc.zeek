# Verify that mDNS messages sent to multicast destinations are not
# correlated by transaction ID. Each message should produce its own
# independent log entry.
# Cases: IPv4 multicast (224.0.0.251), IPv6 multicast (ff02::fb).
#
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/mdns-no-assoc.pcap %INPUT
# @TEST-EXEC: btest-diff dns.log

@load base/protocols/dns
