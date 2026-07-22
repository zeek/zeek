# @TEST-DOC: Tests the DNS max queries limit
#
# @TEST-EXEC: zeek -br $TRACES/dns/conn-count-too-large.pcap dns_max_queries=3 %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/notice/weird
