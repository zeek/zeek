##! This implements handling of "slow peers", i.e. nodes that fall so far behind
##! in message I/O that the local node decides to unpeer them.  Zeek captures
##! this occurrence in logging, eventing, and via telemetry.

@load base/frameworks/telemetry

module Cluster;

global slow_peers_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="slow-peers",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of peering drops due to a neighbor falling too far behind in message I/O",
]);

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	# This is our clue that we're dealing with a drop due to backpressure.
	if ("caf::sec::backpressure_overflow" !in msg)
		return;

	# The peer_removed event indicates that the local endpoint previously
	# connected to the indicated node. We also know that Broker un-peered
	# the other because it fell too far behind in message I/O, per the above
	# message.

	if (! endpoint?$network) {
		Reporter::error(fmt("Missing network info to re-peer with %s", endpoint$id));
		return;
	}

	# Re-establish the peering so Broker's reconnect behavior kicks in once
	# the other endpoint catches up. Broker will periodically re-try this,
	# so it doesn't matter whether we schedule extra wait time for the peer
	# to recover at this point.
	#
	# If we are a passive endpoint (one that got connected to), we may still
	# lose the peering because the other endpoint becomes slow. However,
	# the event signaling this will be Broker::peer_lost, see below.

	local namepair = "";
	local name = "";

	for ( node_name, n in nodes )
		{
		if ( n?$id && n$id == endpoint$id )
			{
			event Cluster::node_slow(node_name, endpoint$id, T);
			namepair = fmt("%s, %s", node_name, endpoint$id);
			name = node_name;
			break;
			}
		}

	if ( name == "" )
		{
		Reporter::warning(fmt("Node %s removed unknown slow peer %s:%s (%s), re-peering",
		                      node, endpoint$network$address, endpoint$network$bound_port,
		                      endpoint$id));
		return;
		}

	local status = Broker::peer(endpoint$network$address,
	                            endpoint$network$bound_port,
	                            Cluster::retry_interval);

	Cluster::log(fmt("removed slow peer %s:%s (%s), re-peering: retry=%s, status=%s",
	                 endpoint$network$address, endpoint$network$bound_port, namepair,
	                 Cluster::retry_interval, status));
	Reporter::warning(fmt("Node %s removed slow peer %s:%s (%s), re-peering",
	                      node, endpoint$network$address, endpoint$network$bound_port, namepair));
	Telemetry::counter_family_inc(slow_peers_cf, vector(name));
}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ("caf::sec::backpressure_overflow" !in msg)
		return;

	# We cannot actively re-establish the peering with the lost node since
	# it connects to us (per Broker's point-to-point topology), so we only
	# log the fact that the loss has happened. Once the other endpoint
	# catches up it still has the peering and will resume it, re-connecting
	# to us as necessary.

	local namepair = "";
	local name = "";

	for ( node_name, n in nodes )
		{
		if ( n?$id && n$id == endpoint$id )
			{
			event Cluster::node_slow(node_name, endpoint$id, F);
			namepair = fmt("%s, %s", node_name, endpoint$id);
			name = node_name;
			break;
			}
		}

	if ( name == "" )
		{
		Reporter::warning(fmt("Node %s lost unknown slow peer %s:%s (%s)",
		                      node, endpoint$network$address,
		                      endpoint$network$bound_port,
		                      endpoint$id));
		return;
		}

	Cluster::log(fmt("lost slow peer %s:%s (%s)",
	                 endpoint$network$address, endpoint$network$bound_port, namepair));
	Reporter::warning(fmt("Node %s lost slow peer %s:%s (%s)",
	                      node, endpoint$network$address, endpoint$network$bound_port, namepair));
	Telemetry::counter_family_inc(slow_peers_cf, vector(name));
	}
