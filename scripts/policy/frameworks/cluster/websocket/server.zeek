##! Script to load for running a single WebSocket server.
##!
##! This script is mostly meant for ad-hoc testing. In a Zeekctl environment,
##! the ``UseWebSocket`` option should be used instead.
##!
##! Note that if :zeek:see:`Cluster::backend` is ``CLUSTER_BACKEND_NONE`` at the
##! time this script is loaded, it loads the ZeroMQ cluster backend and starts a
##! locally running XPUB/XSUB proxy thread. If you instead want to use Broker's hub
##! functionality instead, load policy/frameworks/cluster/backend/broker before
##! loading this script.
##!
##! Note also that this script will raise a fatal error if the cluster backend
##! is :zeek:see:`Cluster::CLUSTER_BACKEND_NONE`, but :zeek:see:`Cluster::nodes`
##! is populated with entries.
@load base/utils/numbers
@load base/frameworks/cluster

# If this script is loaded but no Cluster::backend is yet selected,
# force it to be ZeroMQ!
@if ( Cluster::backend == Cluster::CLUSTER_BACKEND_NONE )

@if ( |Cluster::nodes| > 0 )
event zeek_init() &priority=10
	{
	Reporter::error("Cluster::nodes has entries but Cluster::backend was Cluster::CLUSTER_BACKEND_NONE");
	exit(1);
	}
@else
@load frameworks/cluster/backend/zeromq
redef Cluster::Backend::ZeroMQ::run_proxy_thread = T;
@endif
@endif

event zeek_init() &priority=-100
	{
	local listen_addr = 127.0.0.1;
	local listen_addr_env = getenv("ZEEK_WEBSOCKET_LISTEN_ADDRESS");
	if ( |listen_addr_env| > 0 )
		{
		listen_addr_env = rstrip(lstrip(listen_addr_env, "["), "]");
		listen_addr = to_addr(listen_addr_env);
		}

	local listen_port = 27759/tcp;
	local listen_port_env = getenv("ZEEK_WEBSOCKET_LISTEN_PORT");
	if ( |listen_port_env| > 0 )
		listen_port = count_to_port(extract_count(listen_port_env), tcp);

	Reporter::info(fmt("Running standalone WebSocket server on %s:%s with local cluster backend %s",
	                   listen_addr, listen_port, Cluster::backend));

	if ( ! Cluster::listen_websocket([$listen_addr=listen_addr, $listen_port=listen_port]) )
		Reporter::fatal("failed to listen");
	}
