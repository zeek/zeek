# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2

# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 90

# @TEST-EXEC: btest-diff manager-1/intel.log

@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
example@gmail.com	Intel::EMAIL	source1	test entry	http://some-data-distributor.com/100000
@TEST-END-FILE

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
};
@TEST-END-FILE

@load base/frameworks/cluster
@load base/frameworks/intel
@load frameworks/intel/seen

redef Log::default_rotation_interval = 0secs;
redef Intel::read_files += { "../intel.dat" };

global done_reading = F;
global connected = F;
global log_count = 0;

event zeek_init()
	{
	Broker::subscribe("test");
	}

hook my_removal_hook(c: connection)
	{
	}

event proceed()
	{
	# This is an entirely artificial connection record because reading from
	# a real pcap tends to make this test timeout on CI under ASan.
	local c = connection(
			$id = conn_id($orig_h=1.1.1.1, $orig_p=1/tcp,
			              $resp_h=2.2.2.2, $resp_p=2/tcp),
			$orig = endpoint($size=1, $state=4, $flow_label=0),
			$resp = endpoint($size=1, $state=4, $flow_label=0),
			$start_time=current_time(),
			$duration=1sec,
			$service=set("smtp"),
			$history="ShAdDa",
			$uid="CHhAvVGS1DHFjwGM9",
			$removal_hooks=set(my_removal_hook)
	);

	local iseen = Intel::Seen(
			$indicator="example@gmail.com",
			$indicator_type=Intel::EMAIL,
			$where=Intel::IN_ANYWHERE,
			$conn=c
	);
	Intel::seen(iseen);
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( Cluster::node != "manager-1" )
		return;

	connected = T;

	if ( done_reading )
		Broker::publish("test", proceed);
	}

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( Cluster::node != "manager-1" )
		return;

	done_reading = T;

	if ( connected )
		Broker::publish("test", proceed);
	}

event Intel::log_intel(rec: Intel::Info)
	{
	terminate();
	}
