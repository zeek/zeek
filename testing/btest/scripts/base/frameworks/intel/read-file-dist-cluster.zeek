# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 zeek %INPUT
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: btest-diff manager-1/.stdout
# @TEST-EXEC: btest-diff manager-1/intel.log
# @TEST-EXEC: btest-diff worker-1/.stdout
# @TEST-EXEC: btest-diff worker-2/.stdout

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
};
@TEST-END-FILE

@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
1.2.3.4	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234
1.2.3.4	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234
e@mail.com	Intel::EMAIL	source1	Phishing email source	http://some-data-distributor.com/100000
@TEST-END-FILE

@load base/frameworks/control
redef Log::default_rotation_interval=0sec;

module Intel;

@if ( Cluster::local_node_type() == Cluster::MANAGER )
redef Intel::read_files += { "../intel.dat" };
@endif

redef enum Intel::Where += {
	Intel::IN_A_TEST,
};

event do_it()
	{
	Intel::seen([$host=1.2.3.4, $where=Intel::IN_A_TEST]);
	Intel::seen([$indicator="e@mail.com", $indicator_type=Intel::EMAIL, $where=Intel::IN_A_TEST]);
	}

event zeek_init()
	{
	# Delay the workers searching for hits briefly to allow for the data distribution
	# mechanism to distribute the data to the workers.
	if ( Cluster::local_node_type() == Cluster::WORKER )
		schedule 2sec { do_it() };
	}

global intel_hits=0;
event Intel::log_intel(rec: Intel::Info)
	{
	++intel_hits;
	# There should be 4 hits since each worker is "seeing" 2 things.
	if ( intel_hits == 4 )
		{
		# We're delaying shutdown for a second here to make sure that no other
		# matches happen (which would be wrong!).
		schedule 1sec { Control::shutdown_request() };
		}
	}
