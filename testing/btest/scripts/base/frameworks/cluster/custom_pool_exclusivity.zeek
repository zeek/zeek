# Can't use this test for -O gen-C++ because of multiple simultaneous
# Zeek runs.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_PROXY2_PORT
#
# @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# @TEST-EXEC: btest-bg-run manager ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-2 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff manager/.stdout

@load policy/frameworks/cluster/experimental

global my_pool_spec: Cluster::PoolSpec =
		Cluster::PoolSpec(
			$topic = "zeek/cluster/pool/my_pool",
			$node_type = Cluster::PROXY
			);

global my_pool: Cluster::Pool;

redef Cluster::proxy_pool_spec =
		Cluster::PoolSpec(
			$topic = "zeek/cluster/pool/proxy",
			$node_type = Cluster::PROXY,
			$exclusive = T,
			$max_nodes = 1 
			);

event zeek_init()
	{
	my_pool = Cluster::register_pool(my_pool_spec);
	}

event go_away()
	{
	terminate();
	}

function print_stuff(heading: string)
	{
	print heading;

	local v: vector of count = vector(0, 1, 2, 3, 13, 37, 42, 101);

	for ( i in v )
		{
		print "hrw", v[i], Cluster::hrw_topic(Cluster::proxy_pool, v[i]);
		print "hrw (custom pool)", v[i], Cluster::hrw_topic(my_pool, v[i]);
		}

	local rr_key = "test";

	for ( i in v )
		{
		print "rr", Cluster::rr_topic(Cluster::proxy_pool, rr_key);
		print "rr (custom pool)", Cluster::rr_topic(my_pool, rr_key);
		}

	# Just checking the same keys still map to same topic ...
	for ( i in v )
		{
		print "hrw", v[i], Cluster::hrw_topic(Cluster::proxy_pool, v[i]);
		print "hrw (custom pool)", v[i], Cluster::hrw_topic(my_pool, v[i]);
		}
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
