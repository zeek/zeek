# @TEST-DOC: Verify that BinPAC TLS certificate processing is capped per connection.
#
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls-certificate-chain-limit.pcap %INPUT >out
#
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/ssl

redef SSL::max_certificates = 10;

hook SSL::ssl_finishing(c: connection) &priority=5
	{
	local chain_len = c$ssl?$cert_chain ? |c$ssl$cert_chain| : 0;
	print c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, chain_len;
	}
