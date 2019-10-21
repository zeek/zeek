##! Implements Zeek process supervision configuration options and default
##! behavior.
# TODO: add proper docs

@load ./api
@load base/frameworks/broker

module Supervisor;

export {
	const topic_prefix = "zeek/supervisor" &redef;
}

event zeek_init() &priority=10
	{
	Broker::subscribe(Supervisor::topic_prefix);
	}

event Supervisor::stop_request()
	{
	terminate();
	}

event Supervisor::status_request(reqid: string, nodes: string)
	{
	local res = Supervisor::status(nodes);
	local topic = Supervisor::topic_prefix + fmt("/status_response/%s", reqid);
	Broker::publish(topic, Supervisor::status_response, reqid, res);
	}

event Supervisor::create_request(reqid: string, node: Node)
	{
	local res = Supervisor::create(node);
	local topic = Supervisor::topic_prefix + fmt("/create_response/%s", reqid);
	Broker::publish(topic, Supervisor::create_response, reqid, res);
	}

event Supervisor::destroy_request(reqid: string, nodes: string)
	{
	local res = Supervisor::destroy(nodes);
	local topic = Supervisor::topic_prefix + fmt("/destroy_response/%s", reqid);
	Broker::publish(topic, Supervisor::destroy_response, reqid, res);
	}

event Supervisor::restart_request(reqid: string, nodes: string)
	{
	local res = Supervisor::restart(nodes);
	local topic = Supervisor::topic_prefix + fmt("/restart_response/%s", reqid);
	Broker::publish(topic, Supervisor::restart_response, reqid, res);
	}

function Supervisor::status(nodes: string): Status
	{
	return Supervisor::__status(nodes);
	}

function create(node: Node): string
	{
	return Supervisor::__create(node);
	}

function destroy(nodes: string): bool
	{
	return Supervisor::__destroy(nodes);
	}

function restart(nodes: string): bool
	{
	return Supervisor::__restart(nodes);
	}
