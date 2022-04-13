##! This module provides Management framework functionality present in every
##! cluster node, to allowing Management agents to interact with the nodes.

@load base/frameworks/cluster

@load policy/frameworks/management/agent/config
@load policy/frameworks/management/log

@load ./api
@load ./config

module Management::Node;

# Tag our logs correctly
redef Management::Log::role = Management::NODE;

## The type of dispatch callbacks. These implement a particular dispatch action,
## using the provided string vector as arguments, filling results into the
## provided result record.
type DispatchCallback: function(args: vector of string, res: Management::Result);

## Implementation of the "get_id_value" dispatch. Its only argument is the name
## of the ID to look up.
function dispatch_get_id_value(args: vector of string, res: Management::Result)
	{
	if ( |args| == 0 )
		{
		res$success = F;
		res$error = "get_id_value expects name of global identifier";
		return;
		}

	local val = lookup_ID(args[0]);

	# The following lookup_ID() result strings indicate errors:
	if ( type_name(val) == "string" )
		{
		local valstr: string = val;
		if ( valstr == "<unknown id>" || valstr == "<no ID value>" )
			{
			res$success = F;
			res$error = valstr[1:-1];
			}
		}

	if ( res$success )
		res$data = to_json(val);
	}

global g_dispatch_table: table[string] of DispatchCallback = {
	["get_id_value"] = dispatch_get_id_value,
};

event Management::Node::API::node_dispatch_request(reqid: string, action: vector of string,
    nodes: set[string])
	{
	Management::Log::info(fmt("rx Management::Node::API::node_dispatch_request %s %s %s", reqid, action, nodes));

	if ( |nodes| > 0 && Cluster::node !in nodes )
		{
		Management::Log::debug(fmt(
		    "dispatch %s not targeting this node (%s !in %s), skipping",
		    reqid, Cluster::node, nodes));
		return;
		}

	local res = Management::Result(
	    $reqid = reqid, $node = Cluster::node);

	if ( |action| == 0 )
		{
		res$success = F;
		res$error = "no dispatch arguments provided";
		}
	else if ( action[0] !in g_dispatch_table )
		{
		res$success = F;
		res$error = fmt("dispatch %s unknown", action[0]);
		}

	if ( ! res$success )
		{
		Management::Log::info(fmt("tx Management::Node::API::node_dispatch_response %s",
		    Management::result_to_string(res)));
		event Management::Node::API::node_dispatch_response(reqid, res);
		return;
		}

	g_dispatch_table[action[0]](action[1:], res);

	Management::Log::info(fmt("tx Management::Node::API::node_dispatch_response %s",
	                          Management::result_to_string(res)));
	event Management::Node::API::node_dispatch_response(reqid, res);
	}

event Broker::peer_added(peer: Broker::EndpointInfo, msg: string)
	{
	local epi = Management::Agent::endpoint_info();

	# If this is the agent peering, notify it that we're ready
	if ( peer$network$address == epi$network$address &&
	     peer$network$bound_port == epi$network$bound_port )
		event Management::Node::API::notify_node_hello(Cluster::node);
	}

event zeek_init()
	{
	local epi = Management::Agent::endpoint_info();

	Broker::peer(epi$network$address, epi$network$bound_port, Management::connect_retry);
	Broker::subscribe(node_topic);

	# Events automatically sent to the Management agent.
	local events: vector of any = [
	    Management::Node::API::node_dispatch_response,
	    Management::Node::API::notify_node_hello
	    ];

	for ( i in events )
		Broker::auto_publish(node_topic, events[i]);
	}
