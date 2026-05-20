global tick: event(c: count);
global my_n = 1;


@if ( Cluster::node == "worker-1" )
global offset = 0;
@endif

@if ( Cluster::node == "worker-2" )
global offset = 100000000;
@endif

@if ( Cluster::node == "worker-3" )
global offset = 200000000;
@endif

@if ( Cluster::node == "worker-4" )
global offset = 300000000;
@endif


@if ( Cluster::local_node_type() == Cluster::WORKER )
event tick(c: count)
	{
	my_n = my_n + 1;
	# Reporter::info(fmt("tick(%s)", my_n));
	# Cluster::publish("/lbl/tick", tick, my_n);

	schedule 10msec { tick(my_n) };

	local a = count_to_v4_addr(offset + my_n);
	# Reporter::info(fmt("a %s", a));
	NetControl::drop_address(a, 5sec);
	}

event zeek_init()
	{
	schedule 10msec { tick(1) };
	}
@endif

event NetControl::init()
	{
	local reply_topic = "lbl/acld/reply/";
	if ( Cluster::is_enabled() )
		reply_topic = reply_topic + Cluster::node + "/";

	local pubsub_plugin = NetControl::create_pubsub(NetControl::PubSubConfig(
		$request_topic="lbl/acld/request/",
		$reply_topic=reply_topic,
	));

	NetControl::activate(pubsub_plugin, 0);
	}
