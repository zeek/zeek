# @TEST-DOC: Verify multi-step CNAME resolution with reversed answer order.
# @TEST-EXEC: zeek -b -r $TRACES/dns-cname-chain-reversed.pcap base/protocols/dns
# @TEST-EXEC: btest-diff dns.log
