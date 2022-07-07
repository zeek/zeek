##! Implements Zeek process supervision API and default behavior for its
##! associated (remote) control events.

@load ./api
@load ./control

function Supervisor::status(node: string): Supervisor::Status
	{
	return Supervisor::__status(node);
	}

function Supervisor::create(node: Supervisor::NodeConfig): string
	{
	return Supervisor::__create(node);
	}

function Supervisor::destroy(node: string): bool
	{
	return Supervisor::__destroy(node);
	}

function Supervisor::restart(node: string): bool
	{
	return Supervisor::__restart(node);
	}

function Supervisor::is_supervisor(): bool
	{
	return Supervisor::__is_supervisor();
	}

function Supervisor::is_supervised(): bool
	{
	return Supervisor::__is_supervised();
	}

function Supervisor::node(): Supervisor::NodeConfig
	{
	return Supervisor::__node();
	}

event zeek_init() &priority=10
	{
	if ( Supervisor::is_supervisor() && SupervisorControl::enable_listen )
		{
		# This may fail, possibly with scheduled retries. Any failures
		# already get logged by the listen() implementation, so we don't
		# report additionally.
		Broker::listen();
		}

	Broker::subscribe(SupervisorControl::topic_prefix);
	}

event SupervisorControl::stop_request()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	terminate();
	}

event SupervisorControl::status_request(reqid: string, node: string)
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local res = Supervisor::status(node);
	local topic = SupervisorControl::topic_prefix + fmt("/status_response/%s", reqid);
	Broker::publish(topic, SupervisorControl::status_response, reqid, res);
	}

event SupervisorControl::create_request(reqid: string, node: Supervisor::NodeConfig)
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local res = Supervisor::create(node);
	local topic = SupervisorControl::topic_prefix + fmt("/create_response/%s", reqid);
	Broker::publish(topic, SupervisorControl::create_response, reqid, res);
	}

event SupervisorControl::destroy_request(reqid: string, node: string)
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local res = Supervisor::destroy(node);
	local topic = SupervisorControl::topic_prefix + fmt("/destroy_response/%s", reqid);
	Broker::publish(topic, SupervisorControl::destroy_response, reqid, res);
	}

event SupervisorControl::restart_request(reqid: string, node: string)
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local res = Supervisor::restart(node);
	local topic = SupervisorControl::topic_prefix + fmt("/restart_response/%s", reqid);
	Broker::publish(topic, SupervisorControl::restart_response, reqid, res);
	}

event Supervisor::node_status(node: string, pid: count)
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local topic = SupervisorControl::topic_prefix + "/node_status";
	Broker::publish(topic, SupervisorControl::node_status, node, pid);
	}
