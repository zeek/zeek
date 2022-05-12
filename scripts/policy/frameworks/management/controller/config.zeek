##! Configuration settings for the cluster controller.

@load policy/frameworks/management/config
@load policy/frameworks/management/types

module Management::Controller;

export {
	## The name of this controller. Defaults to the value of the
	## ZEEK_CONTROLLER_NAME environment variable. When that is unset and the
	## user doesn't redef the value, the implementation defaults to
	## "controller-<hostname>".
	const name = getenv("ZEEK_CONTROLLER_NAME") &redef;

	## The controller's stdout log name. If the string is non-empty, Zeek will
	## produce a free-form log (i.e., not one governed by Zeek's logging
	## framework) in Zeek's working directory. If left empty, no such log
	## results.
	##
	## Note that the controller also establishes a "proper" Zeek log via the
	## :zeek:see:`Management::Log` module.
	const stdout_file = "controller.stdout" &redef;

	## The controller's stderr log name. Like :zeek:see:`Management::Controller::stdout_file`,
	## but for the stderr stream.
	const stderr_file = "controller.stderr" &redef;

	## The network address the controller listens on. By default this uses
	## the value of the ZEEK_CONTROLLER_ADDR environment variable, but you
	## may also redef to a specific value. When empty, the implementation
	## falls back to :zeek:see:`Management::default_address`.
	const listen_address = getenv("ZEEK_CONTROLLER_ADDR") &redef;

	## The network port the controller listens on. Counterpart to
	## :zeek:see:`Management::Controller::listen_address`, defaulting to the
	## ZEEK_CONTROLLER_PORT environment variable.
	const listen_port = getenv("ZEEK_CONTROLLER_PORT") &redef;

	## The fallback listen port if :zeek:see:`Management::Controller::listen_port`
	## remains empty.
	const default_port = 2150/tcp &redef;

	## The controller's Broker topic. Clients send requests to this topic.
	const topic = "zeek/management/controller" &redef;

	## An optional custom output directory for stdout/stderr. Agent and
	## controller currently only log locally, not via the Zeek cluster's
	## logger node. This means that if both write to the same log file,
	## output gets garbled.
	const directory = "" &redef;

	## Returns the effective name of the controller.
	global get_name: function(): string;

	## Returns a :zeek:see:`Broker::NetworkInfo` record describing the controller.
	global network_info: function(): Broker::NetworkInfo;

	## Returns a :zeek:see:`Broker::EndpointInfo` record describing the controller.
	global endpoint_info: function(): Broker::EndpointInfo;
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
		ni$address = "127.0.0.1";

	if ( Management::Controller::listen_port != "" )
		ni$bound_port = to_port(Management::Controller::listen_port);
	else
		ni$bound_port = Management::Controller::default_port;

	return ni;
	}

function endpoint_info(): Broker::EndpointInfo
	{
	local epi: Broker::EndpointInfo;

	epi$id = Management::Controller::get_name();
	epi$network = network_info();

	return epi;
	}
