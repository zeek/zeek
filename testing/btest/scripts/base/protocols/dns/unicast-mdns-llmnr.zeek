# Verify that traffic sent to the mDNS and LLMNR service ports is only
# processed as DNS when the responder address is multicast.
#
# @TEST-EXEC: python3 "$(dirname %INPUT)/generate-unicast-mdns-llmnr.py" unicast-mdns-llmnr.pcap
# @TEST-EXEC: zeek -b -C -r unicast-mdns-llmnr.pcap %INPUT
# @TEST-EXEC: test ! -s weird.log
# @TEST-EXEC: test ! -s dns.log

@load base/protocols/dns
