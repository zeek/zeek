# @TEST-DOC: Send any values and observe behavior using zeromq.
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
# @TEST-EXEC: btest-diff ./manager/.stdout
# @TEST-EXEC: btest-diff ./worker-1/.stdout

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap.zeek

redef Log::default_rotation_interval = 0sec;

global finish: event() &is_used;
global ping: event(c: count, what: string, val: any) &is_used;
global pong: event(c: count, what: string, val: any) &is_used;
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global i = 0;
global pongs = 0;

type R: record {
	c: count;
	a: any;
};

event send_any()
	{
	if ( i > 5 )
		return;

	local val: any;
	if ( i == 0 )
		val = 1;
	else if ( i == 1 )
		val = "a string";
	else if ( i == 2 )
		val = 42/tcp;
	else if ( i == 3 )
		val = vector(1, 2, 3);
	else if ( i == 4 )
		val = double_to_time(42.0);
	else
		val = R($c=42, $a=vector(R($c=42, $a="hello")));

	print "sending pings", i, type_name(val), val;
	Cluster::publish_hrw(Cluster::worker_pool, cat(i), ping, i, type_name(val), val);
	Cluster::publish(Cluster::worker_topic, ping, i, type_name(val), val);
	local e = Cluster::make_event(ping, i, type_name(val), val);
	Cluster::publish_hrw(Cluster::worker_pool, cat(i), e);
	++i;
	}

event pong(c: count, what: string, val: any)
	{
	++pongs;
	print "got pong", pongs, "with", c, what, type_name(val), val;

	# The manager sends 6 types of pings, in 3 different ways. The worker
	# answers each ping in two ways, for a total of 36 expected pongs at the
	# manager. Every batch of pings involves 6 pongs.
	if ( pongs == 36 )
		Cluster::publish(Cluster::worker_topic, finish);
	else if ( pongs > 0 && pongs % 6  == 0 )
		{
		# Wait for a batch to complete before sending the next.
		event send_any();
		}
	}

event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name;
	schedule 0.1sec { send_any() };
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
# @TEST-END-FILE


# @TEST-START-FILE worker.zeek
@load ./common.zeek

event ping(c: count, what: string, val: any)
	{
	print "got ping", c, what, type_name(val), cat(val);
	Cluster::publish(Cluster::manager_topic, pong, c, what + " (cluster publish)", val);
	local e = Cluster::make_event(pong, c, what + " (cluster event )", val);
	Cluster::publish(Cluster::manager_topic, e);
	}

event finish()
	{
	print "got finish!";
	terminate();
	}
# @TEST-END-FILE
