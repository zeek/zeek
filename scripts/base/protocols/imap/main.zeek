
module IMAP;

const ports = { 143/tcp } &redef;

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_IMAP, ports);
	}

