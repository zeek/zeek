##! This handles Broker peers that fall so far behind in handling messages that
##! this node sends it that the local Broker endpoint decides to unpeer them.
##! Zeek captures this as follows:
##!
##! - In broker.log, with a regular "peer-removed" entry indicating CAF's reason.
##! - Via eventing through :zeek:see:`Broker::peer_removed` as done in this script.
##!
##! The cluster framework additionally captures the unpeering as follows:
##!
##! - In cluster.log, with a higher-level message indicating the node names involved.
##! - Via telemetry, using a labeled counter.

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( "caf::sec::backpressure_overflow" !in msg ) {
		return;
	}

	if ( ! endpoint?$network ) {
		Reporter::error(fmt("Missing network info to re-peer with %s", endpoint$id));
		return;
	}

	# Re-establish the peering so Broker's reconnect behavior kicks in once
	# the other endpoint catches up. Broker will periodically re-try
	# connecting as necessary. If the other endpoint originally connected to
	# us, our attempt will fail (since we attempt to connect to the peer's
	# ephemeral port), but in that case the peer will reconnect with us once
	# it recovers.
	#
	# We could do this more cleanly by leveraging information from the
	# cluster framework (since it knows who connects to whom), but that
	# would further entangle Broker into it.
	Broker::peer(endpoint$network$address, endpoint$network$bound_port);
}
