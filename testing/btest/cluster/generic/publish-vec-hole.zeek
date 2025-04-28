# @TEST-DOC: Attempt to send an event with holes. It should fail.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: zeek -b --parse-only common.zeek manager.zeek worker.zeek
#
# @TEST-EXEC: btest-bg-run manager "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager zeek -b ../manager.zeek"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b ../worker.zeek"
#
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff ./manager/.stderr
# @TEST-EXEC: btest-diff ./manager/.stdout
# @TEST-EXEC: btest-diff ./worker-1/.stdout
# @TEST-EXEC: btest-diff ./worker-1/.stderr

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap.zeek

redef Log::default_rotation_interval = 0sec;

global finish: event() &is_used;
global ping: event(v: vector of count) &is_used;
global pong: event(v: vector of count) &is_used;
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

event send_pings()
	{
	local v1 = vector(1, 2, 3);

	assert Cluster::publish(Cluster::worker_topic, ping, v1);

	# Publish with a vector with a hole, fails!
	local v2 = vector(1);
	v2[2] = 3;
	assert ! Cluster::publish(Cluster::worker_topic, ping, v2);
	local v3 = vector(4, 5, 6);
	assert Cluster::publish(Cluster::worker_topic, ping, v3);
	}

global pongs = 0;

event pong(v: vector of count)
	{
	++pongs;
	print "got pong", "with", v, |v|;

	# Two of the three pings go through, the worker sends 2 pongs
	# for each ping, so stop after 4.
	if ( pongs == 4 )
		Cluster::publish(Cluster::worker_topic, finish);
	}

event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;
	event send_pings();
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE worker.zeek
@load ./common.zeek

event ping(v: vector of count)
	{
	print "got ping", type_name(v), cat(v), |v|;
	Cluster::publish(Cluster::manager_topic, pong, v);
	local e = Cluster::make_event(pong, v);
	Cluster::publish(Cluster::manager_topic, e);
	}

event finish()
	{
	print "got finish!";
	terminate();
	}
# @TEST-END-FILE
