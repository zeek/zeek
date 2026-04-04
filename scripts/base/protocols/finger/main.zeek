##! Implements base functionality for Finger analysis. We currently do not generate
##! a log file, but just configure the analyzer.

module Finger;

export {
	## Well-known ports for Finger.
	const ports = { 79/tcp } &redef;
}

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_FINGER, ports);
	}
