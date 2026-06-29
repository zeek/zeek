# @TEST-DOC: Test that rpc_max_pending_calls is respected, weirds generated and the rpc_discarded_pending_calls() event raised.
#
# @TEST-EXEC: gunzip -c $TRACES/portmapper-many-unanswered-calls.pcapng.gz | zeek -r - %INPUT >out
#
# @TEST-EXEC: btest-diff-cut -m uid service history duration orig_pkts resp_pkts conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log
# @TEST-EXEC: btest-diff out

global rpc_ports: set[port] = { 111/tcp, } &redef;

# Log the weird repeatedly, otherwise it'll only be logged once.
redef Weird::weird_do_not_ignore_repeats += {
	"RPC_pending_calls_discarded",
};

event zeek_init()
	{
	# The PCAP doesn't actually contain MOUNT, but this allows us to
	# enable the RPC analyzer on the generate traffic.
	Analyzer::register_for_ports(Analyzer::ANALYZER_MOUNT, rpc_ports);
	}

event rpc_discarded_pending_calls(c: connection)
	{
	print "rpc_discarded_pending_calls", network_time(), c$uid;
	}
