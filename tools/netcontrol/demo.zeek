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

@if ( Cluster::local_node_type() == Cluster::MANAGER)
global s = current_time();

type R: record {
	c: count;
	a: addr;
	oa: addr &optional;
	f: double &optional;
};

global miniev: event(a: addr, t: time, td: interval, rvec: vector of R);

global many_args: event(
	c: count,
	i: int,
	t: time,
	td1: interval, td2: interval,
	a1: addr, a2: addr,
	s1: subnet, s2: subnet,
	tr: bool, fa: bool,
	avec: vector of addr,
	rvec: vector of R,
	p1: port, p2: port, p3: port,
	pvec: vector of port
);

global ping: event(c: count);
global pong: event(c: count);

global ping_count = 0;

event pong(c: count) {
	Reporter::info(fmt("Got pong %d", c));
}

event mtick()
	{
	local td = current_time() - s;
	local td2 = s - current_time();
	Cluster::publish("/test/many_args", many_args,
	                 42, -32,
	                 current_time(),
	                 td, td2,
	                 127.0.0.1, [::1],
	                 192.168.0.0/16, [2008::1]/96,
	                 T, F,
	                 vector(127.0.0.1, [2008::1]),
	                 vector(R($c=42, $a=127.0.0.1)),
	                 42/tcp, 1337/udp, 1/unknown,
	                 vector(1/tcp, 2/udp, 3/icmp, 4/unknown),
	);

	Reporter::info(fmt("send miniev: t %s td %s", current_time(), td));
	Cluster::publish("/test/mini", miniev, 192.168.0.1, network_time(), td,
	                 vector(R($c=42, $a=127.0.0.1, $f=42.0),
	                        R($c=4711, $a=[2000::1], $oa=1.2.3.4),
	                        R($c=1337, $a=1.3.3.7)),
	);


	Cluster::publish("/pings/", ping, ++ping_count);
	schedule 1sec { mtick() };
	}

event zeek_init()
	{
	Cluster::subscribe("/pongs/");
	schedule 10msec { mtick() };
	}

event miniev(a: addr, t: time, td: interval, rvec: vector of R)
	{
	Reporter::info(fmt("got miniev: a %s t %s td %s rvec %s", a, t, td, rvec));
	}
@endif
