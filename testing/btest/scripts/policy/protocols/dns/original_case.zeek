# @TEST-EXEC: zeek -b -r $TRACES/dns_original_case.pcap %INPUT
# @TEST-EXEC: btest-diff dns.log
@load protocols/dns/log-original-query-case
