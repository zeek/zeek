redef Cluster::manager_is_logger = F;

redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1],
	["logger-1"] = [$node_type=Cluster::LOGGER, $ip=127.0.0.1, $p=to_port(getenv("LOG_PULL_PORT_1"))],
	["logger-2"] = [$node_type=Cluster::LOGGER, $ip=127.0.0.1, $p=to_port(getenv("LOG_PULL_PORT_2"))],
	["proxy"] = [$node_type=Cluster::PROXY, $ip=127.0.0.1],
	["worker-1"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
	["worker-2"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1],
};
