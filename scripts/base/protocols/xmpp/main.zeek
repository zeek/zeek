
module XMPP;

export {
	## Well-known ports for XMPP.
	const ports = { 5222/tcp, 5269/tcp } &redef;
}

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_XMPP, ports);
	}

