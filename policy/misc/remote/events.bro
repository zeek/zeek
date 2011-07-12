##! Events which can be sent dynamically to Bro instances to retrieve 
##! information about the running process.

module Remote;

export {
	# This event is generated when Bro's configuration may have been updated.
	global configuration_update: event();

	## Event for requesting the value of an ID (a variable).
	global id_request: event(id: string);
	## Event for returning the value of an ID after an :bro:id:`id_request` event.
	global id_response: event(id: string, val: string);
	
	## Requests the current communication status.
	global peer_status_request: event();
	## Returns the current communication status.
	global peer_status_response: event(s: string);
	
	## Requests the current net_stats.
	global net_stats_request: event();
	## Returns the current net_stats.
	global net_stats_response: event(s: string);
}

event id_request(id: string)
	{
	#local msg = fmt("%.6f got event id_request(%s)", network_time(), id);
	#Log::write(CLUSTER, [$ts=network_time(), $msg=msg]);

	local val = lookup_ID(id);
	event id_response(id, fmt("%s", val));
	}
	
event id_response(id: string, val: string)
	{
	#local msg = fmt("%.6f raised event id_response(%s, %s)", network_time(), id, val);
	#Log::write(CLUSTER, [$ts=network_time(), $peer=peer_description, $msg=msg]);
	}

event peer_status_request()
	{
	#local msg = fmt("%.6f got event peer_status_request()", network_time());
	#Log::write(CLUSTER, [$ts=network_time(), $peer=peer_description, $msg=msg]);

	local status = "";
	for ( p in Communication::nodes )
		{
		local peer = Communication::nodes[p];
		if ( ! peer$connected )
			next;

		status += fmt("peer=%s host=%s events_in=? events_out=? ops_in=? ops_out=? bytes_in=? bytes_out=?\n",
					  peer$peer$descr, peer$host);
		}

	event peer_status_response(status);
	}

event peer_status_response(s: string)
	{
	#local msg = fmt("%.6f raised event peer_status_response(%s)", network_time(), s);
	#Log::write(CLUSTER, [$ts=network_time(), $peer=peer_description, $msg=msg]);
	}

event net_stats_request()
	{
	local ns = net_stats();
	local reply = fmt("%.6f recvd=%d dropped=%d link=%d\n", network_time(), 
	                  ns$pkts_recvd, ns$pkts_dropped, ns$pkts_link);
	event net_stats_response(reply);
	}

event net_stats_response(s: string)
	{
	#local msg = fmt("%.6f raised event net_stats_response(%s)", network_time(), s);
	#Log::write(CLUSTER, [$ts=network_time(), $peer=peer_description, $msg=msg]);
	}

