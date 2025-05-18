# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_PROXY2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-2   ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 40
# @TEST-EXEC: btest-diff manager/.stdout

@load policy/frameworks/cluster/experimental

event go_away()
	{
	terminate();
	}

function print_stuff(heading: string)
	{
	print heading;

	local v: vector of count = vector(0, 1, 2, 3, 13, 37, 42, 101);

	for ( i in v )
		print "hrw", v[i], Cluster::hrw_topic(Cluster::proxy_pool, v[i]);

	local rr_key = "test";

	for ( i in v )
		print "rr", Cluster::rr_topic(Cluster::proxy_pool, rr_key);

	# Just checking the same keys still map to same topic ...
	for ( i in v )
		print "hrw", v[i], Cluster::hrw_topic(Cluster::proxy_pool, v[i]);
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node != "manager" )
		return;

	print_stuff("1st stuff");
	local e = Broker::make_event(go_away);
	Broker::publish(Cluster::node_topic("proxy-1"), e);
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Cluster::node != "manager" )
		return;

	if ( name == "proxy-1" )
		{
		print_stuff("2nd stuff");
		local e = Broker::make_event(go_away);
		Broker::publish(Cluster::node_topic("proxy-2"), e);
		}

	if ( name == "proxy-2" )
		{
		print_stuff("no stuff");
		terminate();
		}
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( name == "manager" )
		terminate();
	}
