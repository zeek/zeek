# @TEST-DOC: Tests the DNS max compression depth weird
#
# @TEST-EXEC: zeek -br $TRACES/dns/max-compression-depth.pcap dns_max_compression_chain_depth=5 %INPUT
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/notice/weird
