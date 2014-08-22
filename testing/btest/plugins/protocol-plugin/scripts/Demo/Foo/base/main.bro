
const ports = { 4242/tcp };

event bro_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_FOO, ports);
	}
