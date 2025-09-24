#
# Use this file in a test by copying it into the tests directory:
#
#    @TEST-EXEC: cp $FILES/broker/cluster-layout.zeek .
#
# Then specify @TEST-PORT using the following:
#
#     BROKER_MANAGER_PORT
#     BROKER_LOGGER1_PORT
#     BROKER_LOGGER2_PORT
#     BROKER_PROXY1_PORT
#     BROKER_PROXY2_PORT
#     BROKER_WORKER1_PORT
#     BROKER_WORKER2_PORT
#     BROKER_WORKER3_PORT
#     BROKER_WORKER4_PORT
#
# The existence of the environment variable will add a corresponding node
# to Cluster::nodes.

# Explicitly set the broker backend here.
redef Cluster::backend = Cluster::CLUSTER_BACKEND_BROKER;

# Redef'ed to F if logger-1 or logger-2 are active.
redef Cluster::manager_is_logger = T;

# Minimal cluster-layout for two nodes.
redef Cluster::nodes = {
	["manager"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_MANAGER_PORT"))],
};

# Depending on what environment variables are set, extend the Cluster::nodes table
# with more nodes. This allows tests to control the contents of Cluster::nodes
# just by using TEST-PORT accordingly to the used environment variables.

### Loggers
@if ( getenv("BROKER_LOGGER1_PORT") != "" )
redef Cluster::manager_is_logger = F;
redef Cluster::nodes += {
	["logger-1"] = [$node_type=Cluster::LOGGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_LOGGER1_PORT")), $manager="manager"],
};
@endif

@if ( getenv("BROKER_LOGGER2_PORT") != "" )
redef Cluster::manager_is_logger = F;
redef Cluster::nodes += {
	["logger-2"] = [$node_type=Cluster::LOGGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_LOGGER2_PORT")), $manager="manager"],
};
@endif

### Proxies
@if ( getenv("BROKER_PROXY1_PORT") != "" )
redef Cluster::nodes += {
	["proxy-1"] = [$node_type=Cluster::PROXY, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PROXY1_PORT")), $manager="manager"],
};
@endif

@if ( getenv("BROKER_PROXY2_PORT") != "" )
redef Cluster::nodes += {
	["proxy-2"] = [$node_type=Cluster::PROXY, $ip=127.0.0.1, $p=to_port(getenv("BROKER_PROXY2_PORT")), $manager="manager"],
};
@endif

### Workers
@if ( getenv("BROKER_WORKER1_PORT") != "" )
redef Cluster::nodes += {
	["worker-1"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_WORKER1_PORT")), $manager="manager"],
};
@endif

@if ( getenv("BROKER_WORKER2_PORT") != "" )
redef Cluster::nodes += {
	["worker-2"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_WORKER2_PORT")), $manager="manager"],
};
@endif

@if ( getenv("BROKER_WORKER3_PORT") != "" )
redef Cluster::nodes += {
	["worker-3"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_WORKER3_PORT")), $manager="manager"],
};
@endif

@if ( getenv("BROKER_WORKER4_PORT") != "" )
redef Cluster::nodes += {
	["worker-4"] = [$node_type=Cluster::WORKER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_WORKER4_PORT")), $manager="manager"],
};
@endif
