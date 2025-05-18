# @TEST-DOC: Broker::make_event() together with Cluster::publish_hrw() and Cluster::publish_rr()
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_PROXY2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: zeek -b --parse-only %INPUT
# @TEST-EXEC: btest-bg-run manager   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff manager/.stdout
# @TEST-EXEC: btest-diff proxy-1/.stdout
# @TEST-EXEC: btest-diff proxy-2/.stdout

@load policy/frameworks/cluster/experimental

global q = 0;

event go_away()
	{
	terminate();
	}

event distributed_event_hrw(c: count)
	{
	print "got distributed event hrw", c;
	}

event distributed_event_rr(c: count)
	{
	print "got distributed event rr", c;
	}

function send_stuff(heading: string)
	{
	print heading;

	local v: vector of count = vector(0, 1, 2, 3, 13, 37, 42, 101);
	local e: Broker::Event;

	for ( i in v )
		{
		e = Broker::make_event(distributed_event_hrw, v[i]);
		print "hrw", v[i], Cluster::publish_hrw(Cluster::proxy_pool, v[i], e);
		}

	local rr_key = "test";

	for ( i in v )
		{
		e = Broker::make_event(distributed_event_rr, v[i]);
		print "rr", Cluster::publish_rr(Cluster::proxy_pool, rr_key, e);
		}
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node != "manager" )
		return;

	send_stuff("1st stuff");
	local e = Broker::make_event(go_away);
	Broker::publish(Cluster::node_topic("proxy-1"), e);
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Cluster::node != "manager" )
		return;

	if ( name == "proxy-1" )
		{
		send_stuff("2nd stuff");
		local e = Broker::make_event(go_away);
		Broker::publish(Cluster::node_topic("proxy-2"), e);
		}

	if ( name == "proxy-2" )
		{
		send_stuff("no stuff");
		terminate();
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( name == "manager" )
		terminate();
	}
