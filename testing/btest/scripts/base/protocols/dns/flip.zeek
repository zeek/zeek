# @TEST-EXEC: zeek -b -r $TRACES/dns53.pcap base/protocols/dns
# @TEST-EXEC: btest-diff dns.log
# If the DNS reply is seen first, should be able to correctly set orig/resp.
