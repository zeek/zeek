# Verify that the DNS analyzer drops a message only when BOTH endpoints are
# non-multicast AND both use an mDNS (5353) or LLMNR (5355) port. Every other
# combination of ports and multicast/unicast addresses must still be parsed as
# DNS. The two non-multicast mDNS/LLMNR connections must be absent from dns.log;
# the other seven connections must appear.
#
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/mdns-llmnr-non-multicast.pcap %INPUT
# @TEST-EXEC: test "$(grep -c 'drop-mdns-unicast' dns.log)" = "0"
# @TEST-EXEC: test "$(grep -c 'drop-llmnr-unicast' dns.log)" = "0"
# @TEST-EXEC: btest-diff-cut -m id.orig_h id.orig_p id.resp_h id.resp_p proto query dns.log

@load base/protocols/dns
