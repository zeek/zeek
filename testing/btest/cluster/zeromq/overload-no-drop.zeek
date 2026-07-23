# @TEST-DOC: Workers and proxy publish to the manager topic. They publish as fast as possible for a short period so messages would likely be dropped by sender or receiver due to HWM. The HWM settings are 0 so nothing is dropped at the expense of using more memory. This is verified via metrics and checking the recevied pings on the manager.
#
# @TEST-REQUIRES: have-zeromq
# @TEST-REQUIRES: ! is-windows-ci
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
global finish: event(name: string) &is_used;
global ping: event(sender: string, c: count) &is_used;
global done: event(sender: string, c: count) &is_used;

# Unlimited buffering.
redef Cluster::Backend::ZeroMQ::xpub_sndhwm = 0;
redef Cluster::Backend::ZeroMQ::onloop_queue_hwm = 0;

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

global last_c: table[string] of count &default=0;
global drop_c: table[string] of count &default=0;

event ping(sender: string, c: count)
	{
	local dropped = c  - last_c[sender] - 1;
	if ( dropped > 0 )
		drop_c[sender] += dropped;

	last_c[sender] = c;
	}

event done(sender: string, c: count)
	{
	add nodes_done[sender];
	print "nodes_done", |nodes_done|;

	# Ensure the last ping() and this done()
	# of the same sender have identical values.
	if ( last_c[sender] != c )
		print "ERROR", sender, c, last_c;

	# Ensure nothing was dropped.
	if ( drop_c[sender] != 0 )
		print "ERROR", sender, "had drops";


	if ( |nodes_done| == |nodes_up| )
		event send_finish();
	}

event zeek_done()
	{
	local xpub_drops = Cluster::Backend::ZeroMQ::xpub_drops();
	local onloop_drops = Cluster::Backend::ZeroMQ::onloop_drops();
	print "had xpub_drops?", xpub_drops > 0;
	print "had onloop_drops?", onloop_drops > 0;

	for ( n in test_nodes )
		print fmt("node %s dropped=%s got more than 10k? %s", n, drop_c[n], last_c[n] > 10000);
	}
# @TEST-END-FILE


# @TEST-START-FILE other.zeek
@load ./common.zeek

# Publish state tracking.
global publish_start_time: time = 0;
const publish_duration = 5sec;
global publishes = 0;

# How many events to publish per tick() event.
const batch = 500;
const tick_interval = 1msec;

event tick()
	{
	if ( publish_start_time == 0.0 )
		publish_start_time = current_time();

	if ( (publish_start_time + publish_duration) < current_time() )
		{
		Cluster::publish(Cluster::manager_topic, done, Cluster::node, publishes);
		return;
		}

	local i = batch;
	while ( i > 0 )
		{
		--i;
		++publishes;
		Cluster::publish(Cluster::manager_topic, ping, Cluster::node, publishes);
		}

	schedule tick_interval { tick() };
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
	print "sent more than 10k?", publishes > 10000;
	}
# @TEST-END-FILE
