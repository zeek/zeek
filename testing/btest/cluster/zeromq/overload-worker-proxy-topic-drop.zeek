# @TEST-DOC: Workers and proxy publish to the worker and proxy topics. They publish so fast that messages are dropped a) on their end and b) their own onloop queue as well. The test checks that metrics are incremented and there's no lockup. The manager only coordinates startup and shutdown.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
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
global done: event(name: string) &is_used;
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
global nodes_done: set[string] = set();
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

event done(sender: string)
	{
	local prev = |nodes_done|;
	add nodes_done[sender];
	if ( prev < |nodes_done| )
		print "nodes_done", |nodes_done|;

	if ( |nodes_done| == |test_nodes| )
		event send_finish();
	}

event zeek_done()
	{
	local xpub_drops = Cluster::Backend::ZeroMQ::xpub_drops();
	local onloop_drops = Cluster::Backend::ZeroMQ::onloop_drops();
	print "had xpub_drops?", xpub_drops > 0;
	print "had onloop_drops?", onloop_drops > 0;
	}
# @TEST-END-FILE


# @TEST-START-FILE other.zeek
@load ./common.zeek
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
	if ( |last_c| < |test_nodes|  - 1 )
		return;

	for ( _, lc in last_c )
		if ( lc < total_publishes )
			return;

	# If all nodes sent enough pings, send "done" to the manager.
	Cluster::publish(Cluster::manager_topic, done, Cluster::node);
	}

global publishes = 0;

event tick()
	{
	local i = batch;
	while ( i > 0 )
		{
		--i;
		++publishes;
		Cluster::publish(Cluster::worker_topic, ping, Cluster::node, publishes);
		Cluster::publish(Cluster::proxy_topic, ping, Cluster::node, publishes);

		# Continue sending a single publish for every tick() even
		# if we've published enough in order for the manager to
		# detect we're done. We need to continue here because this
		# node, but also the manager node, may have dropped events.
		if ( publishes >= total_publishes )
			break;
		}

	# Relax publishing if we published enough as to not
	# continue to overload the cluster and have a better
	# chance of termination events going through.
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

	for ( n in test_nodes )
		if ( n != Cluster::node )
			print fmt("node %s dropped=%s", n, drop_c[n] > 0);
	}
# @TEST-END-FILE
