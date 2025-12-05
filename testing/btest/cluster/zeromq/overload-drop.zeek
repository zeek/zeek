# @TEST-DOC: Workers and proxy publish to the manager topic. They publish so fast that messages are dropped a) on their end and b) on the manager as well. The test checks that metrics are incremented and the manager also verifies that not all messages arrived.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: REP_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
# @TEST-EXEC: cp $FILES/zeromq/metrics.zeek zeromq-metrics.zeek
#
# @TEST-EXEC: zeek --parse-only manager.zeek
# @TEST-EXEC: zeek --parse-only other.zeek
#
# @TEST-EXEC: btest-bg-run manager  "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager  zeek -b ../manager.zeek> out"
# @TEST-EXEC: btest-bg-run proxy    "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy    zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../other.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b ../other.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff manager/out
# @TEST-EXEC: btest-diff proxy/out
# @TEST-EXEC: btest-diff worker-1/out
# @TEST-EXEC: btest-diff worker-2/out

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap
@load ./zeromq-metrics

global tick: event() &is_used;
global finish: event(name: string) &is_used;
global ping: event(sender: string, c: count) &is_used;

# How many messages each node publishes in total.
const total_publishes = 100000;
# How many events to publish per tick()
const batch = 100;

# Lower HWMs to provoke drops
redef Cluster::Backend::ZeroMQ::xpub_sndhwm = batch/ 5;
redef Cluster::Backend::ZeroMQ::onloop_queue_hwm = batch / 5;

global test_nodes = set( "proxy", "worker-1", "worker-2" ) &ordered;
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up: set[string] = set();
global nodes_down: set[string] = set();

global sent_finish = F;

event send_finish()
	{
	if ( sent_finish )
		return;

	print "sending finish";
	for ( n in test_nodes )
		Cluster::publish(Cluster::node_topic(n), finish, Cluster::node);

	sent_finish = T;
	}

event Cluster::node_up(name: string, id: string)
	{
	add nodes_up[name];
	print "nodes_up", |nodes_up|;

	# Get the ball rolling once all nodes are available, sending the
	# first tick() to proxy and workers.
	if ( |nodes_up| == |test_nodes| )
		{
		Cluster::publish(Cluster::worker_topic, tick);
		Cluster::publish(Cluster::proxy_topic, tick);
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	add nodes_down[name];
	print "nodes_down", |nodes_down|;
	if ( |nodes_down| == |test_nodes| )
		terminate();
	}

global last_c: table[string] of count &default=0;
global drop_c: table[string] of count &default=0;

event ping(sender: string, c: count)
	{
	local dropped = c  - last_c[sender] - 1;
	if ( dropped > 0 )
		drop_c[sender] += dropped;

	last_c[sender] = c;

	# Check if all senders sent enough messages. If not,
	# wait for the next ping to arrive.
	for ( _, lc in last_c )
		if ( lc < total_publishes )
			return;

	# Send finish just once.
	event send_finish();
	}

event zeek_done()
	{
	local xpub_drops = Cluster::Backend::ZeroMQ::xpub_drops();
	local onloop_drops = Cluster::Backend::ZeroMQ::onloop_drops();
	print "had xpub_drops?", xpub_drops > 0;
	print "had onloop_drops?", onloop_drops > 0;

	for ( n in test_nodes )
		print fmt("node %s dropped=%s", n, drop_c[n] > 0);

	}
# @TEST-END-FILE


# @TEST-START-FILE other.zeek
@load ./common.zeek

global publishes = 0;

event tick()
	{
	local i = batch;
	while ( i > 0 )
		{
		--i;
		++publishes;
		Cluster::publish(Cluster::manager_topic, ping, Cluster::node, publishes);

		# Continue sending a single publish for every tick() even
		# if we've published enough in order for the manager to
		# detect we're done. We need to continue here because this
		# node, but also the manager node, may have dropped events.
		if ( publishes >= total_publishes )
			break;
		}

	# Relax publishing if we published enough so the manager
	# isn't totally overloaded.
	local s = publishes < total_publishes ? 0sec : 0.05sec;
	schedule s { tick() };
	}

event finish(name: string)
	{
	terminate();
	}

event zeek_done()
	{
	local xpub_drops = Cluster::Backend::ZeroMQ::xpub_drops();
	local onloop_drops = Cluster::Backend::ZeroMQ::onloop_drops();
	print "had xpub_drops?", xpub_drops > 0;
	print "had onloop_drops?", onloop_drops > 0;
	}
# @TEST-END-FILE
