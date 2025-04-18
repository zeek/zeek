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

event Broker::peer_removed(ep: Broker::EndpointInfo, msg: string)
	{
	if ( "caf::sec::backpressure_overflow" !in msg ) {
		return;
	}

	if ( ! ep?$network ) {
		Reporter::error(fmt("Missing network info to re-peer with %s", ep$id));
		return;
	}

	# Re-establish the peering. Broker will periodically re-try connecting
	# as necessary. Do this only if the local node originally established
	# the peering, otherwise we would connect to an ephemeral client-side
	# TCP port that doesn't listen. If we didn't originally establish the
	# peering, the other side will retry anyway.
	if ( Broker::is_outbound_peering(ep$network$address, ep$network$bound_port) )
		Broker::peer(ep$network$address, ep$network$bound_port);
}
