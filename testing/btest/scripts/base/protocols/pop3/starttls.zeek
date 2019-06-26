# @TEST-EXEC: zeek -C -b -r $TRACES/tls/pop3-starttls.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log

@load base/protocols/conn
@load base/frameworks/dpd
@load base/protocols/ssl

module POP3;

const ports = {
	110/tcp
};
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_POP3, ports);
	}
