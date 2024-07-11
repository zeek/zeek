##! Configuration settings for the cluster controller.

@load policy/frameworks/management

module Management::Controller;

export {
	## The name of this controller. Defaults to the value of the
	## ZEEK_CONTROLLER_NAME environment variable. When that is unset and the
	## user doesn't redef the value, the implementation defaults to
	## "controller-<hostname>".
	const name = getenv("ZEEK_CONTROLLER_NAME") &redef;

	## The controller's stdout log name. If the string is non-empty, Zeek
	## will produce a free-form log (i.e., not one governed by Zeek's
	## logging framework) in the controller's working directory. If left
	## empty, no such log results.
	##
	## Note that the controller also establishes a "proper" Zeek log via the
	## :zeek:see:`Management::Log` module.
	const stdout_file = "stdout" &redef;

	## The controller's stderr log name. Like :zeek:see:`Management::Controller::stdout_file`,
	## but for the stderr stream.
	const stderr_file = "stderr" &redef;

	## The network address the controller listens on for Broker clients. By
	## default this uses the ZEEK_CONTROLLER_ADDR environment variable, but
	## you may also redef to a specific value. When empty, the
	## implementation falls back to :zeek:see:`Management::default_address`.
	const listen_address = getenv("ZEEK_CONTROLLER_ADDR") &redef;

	## The network port the controller listens on for Broker clients.
	## Defaults to the ZEEK_CONTROLLER_PORT environment variable.
	## When that is not set, the implementation falls back to
	## :zeek:see:`Management::Controller::default_port`.
	const listen_port = getenv("ZEEK_CONTROLLER_PORT") &redef;

	## The fallback listen port if :zeek:see:`Management::Controller::listen_port`
	## remains empty. When set to 0/unknown, the controller won't listen
	## for Broker connections. Don't do this if your management agents
	## connect to the controller (instead of the default other way around),
	## as they require Broker connectivity.
	const default_port = 2150/tcp &redef;

	## The network address the controller listens on for websocket
	## clients. By default this uses the ZEEK_CONTROLLER_WEBSOCKET_ADDR
	## environment variable, but you may also redef to a specific
	## value. When empty, the implementation falls back to
	## :zeek:see:`Management::default_address`.
	const listen_address_websocket = getenv("ZEEK_CONTROLLER_WEBSOCKET_ADDR") &redef;

	## The network port the controller listens on for websocket clients.
	## Defaults to the ZEEK_CONTROLLER_WEBSOCKET_PORT environment
	## variable. When that is not set, the implementation falls back to
	## :zeek:see:`Management::Controller::default_port_websocket`.
	const listen_port_websocket = getenv("ZEEK_CONTROLLER_WEBSOCKET_PORT") &redef;

	## The fallback listen port if :zeek:see:`Management::Controller::listen_port_websocket`
	## remains empty. When set to 0/unknown, the controller won't listen
	## for websocket clients.
	const default_port_websocket = 2149/tcp &redef;

	## Whether the controller should auto-assign Broker listening ports to
	## cluster nodes that need them and don't have them explicitly specified
	## in cluster configurations.
	const auto_assign_broker_ports = T &redef;
	const auto_assign_ports = T &redef &deprecated="Remove in v7.1: replaced by auto_assign_broker_ports.";

	## The TCP start port to use for auto-assigning cluster node listening
	## ports, if :zeek:see:`Management::Controller::auto_assign_broker_ports` is
	## enabled (the default) and nodes don't come with those ports assigned.
	const auto_assign_broker_start_port = 2200/tcp &redef;
	const auto_assign_start_port = 2200/tcp &redef &deprecated="Remove in v7.1: replaced by auto_assign_broker_start_port.";

	## Whether the controller should auto-assign metrics ports for Prometheus
	## to nodes that need them and don't have them explicitly specified in
	## their cluster configurations.
	const auto_assign_metrics_ports = T &redef;

	## The TCP start port to use for auto-assigning metrics exposition ports
	## for Prometheus, if :zeek:see:`Management::Controller::auto_assign_metrics_ports`
	## is enabled (the default).
	const auto_assign_metrics_start_port = 9000/tcp &redef;

	## The controller's Broker topic. Clients send requests to this topic.
	const topic = "zeek/management/controller" &redef;

	## An optional custom output directory for stdout/stderr. Agent and
	## controller currently only log locally, not via the Zeek cluster's
	## logger node. This means that if both write to the same log file,
	## output gets garbled.
	const directory = "" &redef;

	## The name of the Broker store the controller uses to persist internal
	## state to disk.
	const store_name = "controller";

	## Returns the effective name of the controller.
	global get_name: function(): string;

	## Returns a :zeek:see:`Broker::NetworkInfo` record describing the
	## controller's Broker connectivity.
	global network_info: function(): Broker::NetworkInfo;

	## Returns a :zeek:see:`Broker::NetworkInfo` record describing the
	## controller's websocket connectivity.
	global network_info_websocket: function(): Broker::NetworkInfo;

	## Returns a :zeek:see:`Broker::EndpointInfo` record describing the
	## controller's Broker connectivity.
	global endpoint_info: function(): Broker::EndpointInfo;

	## Returns a :zeek:see:`Broker::EndpointInfo` record describing the
	## controller's websocket connectivity.
	global endpoint_info_websocket: function(): Broker::EndpointInfo;
}

function get_name(): string
	{
	if ( name != "" )
		return name;

	return fmt("controller-%s", gethostname());
	}

function network_info(): Broker::NetworkInfo
	{
	local ni: Broker::NetworkInfo;

	if ( Management::Controller::listen_address != "" )
		ni$address = Management::Controller::listen_address;
	else if ( Management::default_address != "" )
		ni$address = Management::default_address;
	else
		ni$address = "0.0.0.0";

	if ( Management::Controller::listen_port != "" )
		ni$bound_port = to_port(Management::Controller::listen_port);
	else
		ni$bound_port = Management::Controller::default_port;

	return ni;
	}

function network_info_websocket(): Broker::NetworkInfo
	{
	local ni: Broker::NetworkInfo;

	if ( Management::Controller::listen_address_websocket != "" )
		ni$address = Management::Controller::listen_address_websocket;
	else if ( Management::default_address != "" )
		ni$address = Management::default_address;
	else
		ni$address = "0.0.0.0";

	if ( Management::Controller::listen_port_websocket != "" )
		ni$bound_port = to_port(Management::Controller::listen_port_websocket);
	else
		ni$bound_port = Management::Controller::default_port_websocket;

	return ni;
	}

function endpoint_info(): Broker::EndpointInfo
	{
	local epi: Broker::EndpointInfo;

	epi$id = Management::Controller::get_name();
	epi$network = network_info();

	return epi;
	}

function endpoint_info_websocket(): Broker::EndpointInfo
	{
	local epi: Broker::EndpointInfo;

	epi$id = Management::Controller::get_name();
	epi$network = network_info_websocket();

	return epi;
	}
