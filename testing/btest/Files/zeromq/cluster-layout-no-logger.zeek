redef Cluster::manager_is_logger = T;

redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("LOG_PULL_PORT"))],
	["proxy"] = [$node_type=Cluster::PROXY, $ip=127.0.0.1],
	["worker-1"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
	["worker-2"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
};
