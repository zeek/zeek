# @TEST-DOC: Query the Prometheus endpoint on 9911 and smoke check that zeek_version_info{...} is contained in the response for all cluster nodes.
# Note compilable to C++ due to globals being initialized to a record that
# has an opaque type as a field.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-PORT: BROKER_PORT1
# @TEST-PORT: BROKER_PORT2
# @TEST-PORT: BROKER_PORT3
# @TEST-PORT: BROKER_PORT4
# @TEST-PORT: BROKER_PORT4
# @TEST-PORT: BROKER_TEST_METRICS_PORT
#
# @TEST-REQUIRES: which curl
# @TEST-EXEC: zeek --parse-only %INPUT
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run logger-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=logger-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run proxy-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=proxy-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff manager-1/.stdout

@load base/frameworks/cluster
@load base/frameworks/telemetry
@load base/utils/active-http

# Query the Prometheus endpoint using ActiveHTTP for testing, oh my.
event run_test()
	{
	local url = fmt("http://localhost:%s/metrics", port_to_count(Broker::metrics_port));
	when [url] ( local response = ActiveHTTP::request([$url=url]) )
		{
		if  ( response$code != 200 )
			{
			print fmt("ERROR: %s", response);
			exit(1);
			}

		# Grumble grumble, ActiveHTTP actually joins away the \n characters
		# from the response. Not sure how that's helpful. We simply
		# grep out the zeek_version_info{...}  endpoint="..." pieces and
		# expect one for each node to exist as a smoke test.
		local version_infos = find_all(response$body, /zeek_version_info\{[^}]+\}/);
		local endpoints: vector of string;
		for ( info in version_infos )
			for ( ep in find_all(info, /endpoint=\"[^"]+\"/))
				endpoints += ep;

		print sort(endpoints, strcmp);

		terminate();
		}
	timeout 10sec
		{
		# This is bad.
		print "ERROR: HTTP request timeout";
		exit(1);
		}
	}

global node_count = 0;

@if ( Cluster::node == "manager-1" )
# Use a dynamic metrics port for testing to avoid colliding on 9911/tcp
# when running tests in parallel.
global orig_metrics_port = Broker::metrics_port;
redef Broker::metrics_port = to_port(getenv("BROKER_TEST_METRICS_PORT"));

event zeek_init()
	{
	print Cluster::node, "original Broker::metrics_port", orig_metrics_port;
	}

event Cluster::node_up(name: string, id: string)
	{
	++node_count;
	# Run the test after all nodes are up and metrics_export_interval
	# has passed at least once.
	if ( Cluster::node == "manager-1" )
		if ( node_count == 3 )
			schedule 2 * Broker::metrics_export_interval { run_test() };
	}
@endif

# If any node goes down, terminate() right away.
event Cluster::node_down(name: string, id: string)
	{
	print fmt("node_down on %s", Cluster::node);
	terminate();
	}

@TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT1"))],
	["logger-1"] = [$node_type=Cluster::LOGGER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT2")), $manager="manager-1"],
	["proxy-1"] = [$node_type=Cluster::PROXY,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT3")), $manager="manager-1"],
	["worker-1"] = [$node_type=Cluster::WORKER,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PORT4")), $manager="manager-1", $interface="eth0"],
};
@TEST-END-FILE
