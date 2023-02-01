##! Implements base functionality for Finger analysis. We currently do not generate
##! a log file, but just configure the analyzer.

module Finger;

export {
	const ports = { 79/tcp };
	redef likely_server_ports += { ports };
}

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_FINGER, ports);
	}
