##! Script side for the Bench analyzer.
##!
##! This can be run with Bench::t=spicy or Bench::t=binpac on the command-line
##! to compare the implementation of the same protocol:
##!
##!     hyperfine -r 3 -w1 -L analyzer 'spicy,binpac,none' \
##!       'taskset -c 0 zeek -D -C -b protocols/bench -r bench-traffic-128-10000.pcap  Bench::t={analyzer}'
##!
##! When running with Bench::do_print=T, it'll print all handled events
##! to stdout, allowing to compare the implementations.
module Bench;

export {
	option t = "spicy";
	const do_print = F &redef;
	const ports = { 7000/tcp } &redef;
	redef likely_server_ports += { ports };
}

event zeek_init() &priority=5
	{
	if ( t == "spicy" )
		Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_BENCH, ports);
	else if ( t == "binpac" )
		Analyzer::register_for_ports(Analyzer::ANALYZER_BINPAC_BENCH, ports);
	else if ( t == "none" )
		{
		# nada
		}
	else
		{
		Reporter::error(fmt("unsupported %s", t));
		exit(1);
		}

	if ( ! do_print )
		disable_event_group("Bench::do_print");
	}

global cc = 0;
event bench_request(c: connection, version: count, id: count, length: count, data: string) {
	++cc;
}

event bench_reply(c: connection, version: count, id: count, length: count) {
	++cc;
}

event bench_request(c: connection, version: count, id: count, length: count, data: string) &group="Bench::do_print" {
	print "bench_request", c$uid, c$id$orig_p, version, id, length, |data|, data[:10];
}

event bench_reply(c: connection, version: count, id: count, length: count) &group="Bench::do_print" {
	print "bench_reply", c$uid, c$id$orig_p, version, id, length;
}

event zeek_done() {
	print cc;
}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print "analyzer_violation!", info$reason, info$aid, info$c$uid;
	}
