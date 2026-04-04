# @TEST-EXEC: zeek -b -r $TRACES/dns-inverse-query.pcap %INPUT
# @TEST-EXEC: test ! -e dns.log

@load protocols/dns/auth-addl
