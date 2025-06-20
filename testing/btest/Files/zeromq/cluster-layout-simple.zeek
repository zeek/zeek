redef Cluster::manager_is_logger = F;

const node_ip = 127.0.0.1 &redef;

# If ZEEK_CLUSTER_IP is set, populate the cluster-layout's Node$ip fields with it.
const cluster_ip_env = getenv("BTEST_CLUSTER_IP");
@if ( cluster_ip_env != "" )
redef node_ip = to_addr(cluster_ip_env);
@endif

redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=node_ip],
	["logger"] = [$node_type=Cluster::LOGGER, $ip=node_ip, $p=to_port(getenv("LOG_PULL_PORT"))],
	["proxy"] = [$node_type=Cluster::PROXY, $ip=node_ip],
	["worker-1"] = [$node_type=Cluster::WORKER, $ip=node_ip],
	["worker-2"] = [$node_type=Cluster::WORKER, $ip=node_ip],
};
