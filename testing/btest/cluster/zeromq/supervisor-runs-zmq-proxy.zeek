# @TEST-DOC: Test a Zeek cluster where the ZeroMQ proxy thread is spawned by the supervisor instead of the manager.
#
# @TEST-REQUIRES: have-zeromq
#
# @TEST-GROUP: cluster-zeromq
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT

# @TEST-EXEC: chmod +x ./check-cluster-log.sh
#
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: btest-bg-run supervisor "ZEEKPATH=$ZEEKPATH:.. && zeek -j ../supervisor-runs-zmq-proxy.zeek >out"
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff supervisor/cluster.log

redef Log::default_rotation_interval = 0secs;
redef Log::flush_interval = 0.01sec;

@load ./zeromq-test-bootstrap

redef Cluster::Backend::ZeroMQ::run_proxy_thread = F;

# The supervisor peeks into logger/cluster.log to initate a shutdown when
# all nodes have said hello to each other. See the check-cluster.log.sh
# script below.
event check_cluster_log() {
	system_env("../check-cluster-log.sh", table(["SUPERVISOR_PID"] = cat(getpid())));

	schedule 0.1sec { check_cluster_log() };
}

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	if ( ! Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread() )
		Reporter::fatal("Failed to spawn proxy thread");

	local cluster: table[string] of Supervisor::ClusterEndpoint;
	cluster["manager"] = [$role=Supervisor::MANAGER, $host=127.0.0.1, $p=0/unknown];
	cluster["logger"] = [$role=Supervisor::LOGGER, $host=127.0.0.1, $p=to_port(getenv("LOG_PULL_PORT"))];
	cluster["proxy"] = [$role=Supervisor::PROXY, $host=127.0.0.1, $p=0/unknown];
	cluster["worker-1"] = [$role=Supervisor::WORKER, $host=127.0.0.1, $p=0/unknown];
	cluster["worker-2"] = [$role=Supervisor::WORKER, $host=127.0.0.1, $p=0/unknown];

	for ( n, ep in cluster )
		{
		local sn = Supervisor::NodeConfig($name=n, $bare_mode=T, $cluster=cluster, $directory=n);
		local res = Supervisor::create(sn);

		if ( res != "" )
			print fmt("supervisor failed to create node '%s': %s", n, res);
		}

	# Start polling the cluster.log
	event check_cluster_log();
	}

# @TEST-START-FILE check-cluster-log.sh
#!/bin/sh
#
# This script checks logger/cluster.log until the expected number
# of log entries have been observed and puts a normalized version
# into the current directory. This runs from the supervisor.
if [ ! -f logger/cluster.log ]; then
	exit 1;
fi

if [ -f DONE ]; then
	exit 0
fi

# Remove hostname and pid from node id in message.
zeek-cut node message < logger/cluster.log | sed -r 's/_[^_]+_[0-9]+_/_<hostname>_<pid>_/g' | sort > cluster.log

if [ $(wc -l < cluster.log) = 20 ]; then
	echo "DONE!" >&2
	# Trigger shutdown through supervisor.
	kill ${ZEEK_ARG_SUPERVISOR_PID};
	echo "DONE" > DONE
fi
# @TEST-END-FILE
