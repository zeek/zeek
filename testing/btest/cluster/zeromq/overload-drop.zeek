# @TEST-DOC: Workers and proxy publish to the manager topic. They publish so fast that messages should be dropped a) on their end and b) on the manager's onloop queue as well. The manager tests in ping() if the sender dropped and also if its own onloop queue had dropped and only then starts sending finish() events to all nodes.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: ! is-windows-ci
# @TEST-REQUIRES: ! ( have-asan && test -n "${CI}" )
# @TEST-REQUIRES: ! ( have-ubsan && test -n "${CI}" )
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

redef Log::default_rotation_interval = 0 secs;

global tick: event() &is_used;
global finish: event(name: string) &is_used;
global ping: event(sender: string, c: count, xdc: count) &is_used;

# How many events to publish per tick()
const batch = 500;

# Lower HWMs to provoke drops fast!
redef Cluster::Backend::ZeroMQ::xpub_sndhwm = batch / 5;
redef Cluster::Backend::ZeroMQ::xsub_rcvhwm = batch / 10;
redef Cluster::Backend::ZeroMQ::onloop_queue_hwm = batch / 10;

# Helpers to get drop counts.
global xpub_drops: function(): count = Cluster::Backend::ZeroMQ::xpub_drops;
global onloop_drops: function(): count = Cluster::Backend::ZeroMQ::onloop_drops;

global test_nodes = set( "proxy", "worker-1", "worker-2" ) &ordered;
# @TEST-END-FILE


# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_up: set[string] = set();
global nodes_down: set[string] = set();

# last_c tracks the last publish offset from other nodes.
global last_c: table[string] of count &default=0;

# drop_c is incremented whenever c from sender and last_c[sender]
# have non-zero difference.
global drop_c: table[string] of count;

# xpub_drop_c tracks the xpub_drops of the node on the
# ZeroMQ side. This is transported in the ping() event
# as xdc argument (xpub drop count).
global xpub_drop_c: table[string] of count;

# The manager sends finish events via a scheduled event,
# but at a fairly low rate.
global scheduled_finish = F;
global sent_finish = F;

event send_finish()
	{
	# Reset the timer for ping() to re-arm it.
	scheduled_finish = F;

	if ( ! sent_finish )
		{
		print "sending first finish";
		sent_finish = T;
		}

	for ( n in test_nodes )
		Cluster::publish(Cluster::node_topic(n), finish, Cluster::node);
	}

event Cluster::node_up(name: string, id: string)
	{
	add nodes_up[name];
	xpub_drop_c[name] = 0;
	drop_c[name] = 0;

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

# Manager gets a ping() from another node.
event ping(sender: string, c: count, xdc: count)
	{
	local dropped = c  - last_c[sender] - 1;
	if ( dropped > 0 )
		drop_c[sender] += dropped;

	last_c[sender] = c;

	xpub_drop_c[sender] = xdc;

	for ( _, xdc in xpub_drop_c )
		if ( xdc == 0 )
			return;

	# Check if the manager itself already dropped onloop messages.
	if ( onloop_drops() == 0 )
		return;

	# Coalesce multiple finish() events together.
	if ( ! scheduled_finish )
		{
		schedule 10msec { send_finish() };
		scheduled_finish = T;
		}
	}

event zeek_done()
	{
	print "had onloop_drops?", onloop_drops() > 0;

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
	local xdc = xpub_drops();

	while ( i > 0 )
		{
		--i;
		++publishes;
		Cluster::publish(Cluster::manager_topic, ping,
		                 Cluster::node, publishes, xdc);
		}

	schedule 1msec { tick() };
	}

event finish(name: string)
	{
	terminate();
	}

event zeek_done()
	{
	print "had xpub_drops?", xpub_drops() > 0;
	print "had onloop_drops?", onloop_drops() > 0;
	}
# @TEST-END-FILE
