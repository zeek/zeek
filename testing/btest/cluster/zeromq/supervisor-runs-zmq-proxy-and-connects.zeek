# @TEST-DOC: Test a Zeek cluster where the ZeroMQ proxy thread is spawned by the supervisor instead of the manager. The supervisor itself connects with the XPUB/XSUB sockets using Cluster::init() and receives and sends events without actually being a proper Cluster::node.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
# @TEST-REQUIRES: ! is-windows-ci
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# @TEST-EXEC: btest-bg-run supervisor "ZEEKPATH=$ZEEKPATH:.. && zeek -j ../supervisor-runs-zmq-proxy-and-connects.zeek"
# @TEST-EXEC: btest-bg-wait 30
#
# @TEST-EXEC: btest-diff supervisor/.stdout
# @TEST-EXEC: btest-diff supervisor/.stderr
#
# @TEST-EXEC: btest-diff supervisor/logger/stdout
# @TEST-EXEC: btest-diff supervisor/manager/stdout
# @TEST-EXEC: btest-diff supervisor/proxy/stdout
# @TEST-EXEC: btest-diff supervisor/worker-1/stdout
# @TEST-EXEC: btest-diff supervisor/worker-2/stdout

global xsub_endpoint = fmt("tcp://127.0.0.1:%s", port_to_count(to_port(getenv("XPUB_PORT"))));
global xpub_endpoint = fmt("tcp://127.0.0.1:%s", port_to_count(to_port(getenv("XSUB_PORT"))));

# Event published by each cluster member to the supervisor topic
# when they see their cluster_started() event.
global we_are_all_up: event(from: string) &is_used;
global you_are_all_up: event(round: count) &is_used;

@if ( Supervisor::is_supervisor() )

### SUPERVISOR

# The supervisor does not load the full backend/zeromq package to avoid
# participating in the Zeek cluster, but does load all options and redefs,
# but no event handlers that would start the interactions from main.
@load frameworks/cluster/backend/zeromq/options

redef Cluster::Backend::ZeroMQ::listen_xpub_endpoint = xpub_endpoint;
redef Cluster::Backend::ZeroMQ::listen_xsub_endpoint = xsub_endpoint;

redef Cluster::Backend::ZeroMQ::connect_xsub_endpoint = xpub_endpoint;
redef Cluster::Backend::ZeroMQ::connect_xpub_endpoint = xsub_endpoint;

global nodes_up: set[string];
global round = 1;

# Supervisor gets we_are_all_up() from each of the nodes when they see
# cluster_started(). The supervisor publishes you_are_all_up() to
# each of the node topics, then await a second round of we_are_all_up()
event we_are_all_up(from: string)
	{
	add nodes_up[from];
	print "we_are_all_up", "round", round, "nodes_up", |nodes_up|;

	if ( |nodes_up| == 5 )
		{
		if ( round == 1 )
			{
			Cluster::publish(Cluster::logger_topic, you_are_all_up, round);
			Cluster::publish(Cluster::manager_topic, you_are_all_up, round);
			Cluster::publish(Cluster::proxy_topic, you_are_all_up, round);
			Cluster::publish(Cluster::worker_topic, you_are_all_up, round);

			delete nodes_up;
			round = 2;
			}
		else
			{
			print "got all we_are_all_up round 2";
			terminate();
			}
		}
	}

event zeek_init()
	{
	if ( ! Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread() )
		Reporter::fatal("Failed to spawn proxy thread");

	if ( ! Cluster::init() )
		Reporter::fatal("Failed to Cluster::init()");

	Cluster::subscribe("zeek.supervisor.test");

	local cluster: table[string] of Supervisor::ClusterEndpoint;
	cluster["manager"] = [$role=Supervisor::MANAGER, $host=127.0.0.1, $p=0/unknown];
	cluster["logger"] = [$role=Supervisor::LOGGER, $host=127.0.0.1, $p=to_port(getenv("LOG_PULL_PORT"))];
	cluster["proxy"] = [$role=Supervisor::PROXY, $host=127.0.0.1, $p=0/unknown];
	cluster["worker-1"] = [$role=Supervisor::WORKER, $host=127.0.0.1, $p=0/unknown];
	cluster["worker-2"] = [$role=Supervisor::WORKER, $host=127.0.0.1, $p=0/unknown];

	for ( n, ep in cluster )
		{
		local sn = Supervisor::NodeConfig(
			$name=n,
			$bare_mode=T,
			$cluster=cluster,
			$directory=n,
			$stdout_file = "stdout",
			$stderr_file = "stderr");
		local res = Supervisor::create(sn);

		if ( res != "" )
			print fmt("supervisor failed to create node '%s': %s", n, res);
		}
	}
@else

### SUPERVISED

# The supervised nodes connect to the XPUB/XSUB proxy running in the supervisor.
@load frameworks/cluster/backend/zeromq

# Ensure the manager does not run the proxy thread (default).
redef Cluster::Backend::ZeroMQ::run_proxy_thread = F;

redef Cluster::Backend::ZeroMQ::connect_xsub_endpoint = xpub_endpoint;
redef Cluster::Backend::ZeroMQ::connect_xpub_endpoint = xsub_endpoint;
redef Cluster::Backend::ZeroMQ::listen_xpub_endpoint = "";
redef Cluster::Backend::ZeroMQ::listen_xsub_endpoint = "";

@load frameworks/cluster/experimental


# A supervised node publishes we_are_all_up() with its own name to the
# supervisor test topic.
event Cluster::Experimental::cluster_started()
	{
	print "cluster_started";
	Cluster::publish("zeek.supervisor.test", we_are_all_up, Cluster::node);
	}

# Event from the supervisor when it got all we_are_all_up() for the first time.
event you_are_all_up(round: count)
	{
	print "got you_are_all_up", round;
	Cluster::publish("zeek.supervisor.test", we_are_all_up, Cluster::node);
	}
@endif
