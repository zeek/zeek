
@load frameworks/control

# If an instance is a controllee, it implicitly needs to listen for remote 
# connections.
@load frameworks/communication/listen-clear

module Control;

event Control::id_value_request(id: string)
	{
	local val = lookup_ID(id);
	event Control::id_value_response(id, fmt("%s", val));
	}

event Control::peer_status_request()
	{
	local status = "";
	for ( p in Communication::nodes )
		{
		local peer = Communication::nodes[p];
		if ( ! peer$connected )
			next;

		status += fmt("peer=%s host=%s events_in=? events_out=? ops_in=? ops_out=? bytes_in=? bytes_out=?\n",
					  peer$peer$descr, peer$host);
		}

	event Control::peer_status_response(status);
	}

event Control::net_stats_request()
	{
	local ns = net_stats();
	local reply = fmt("%.6f recvd=%d dropped=%d link=%d\n", network_time(), 
	                  ns$pkts_recvd, ns$pkts_dropped, ns$pkts_link);
	event Control::net_stats_response(reply);
	}
	
event Control::configuration_update_request()
	{
	# Generate the alias event. 
	event Control::configuration_update();
	
	# Don't need to do anything in particular here, it's just indicating that
	# the configuration is going to be updated.  This event could be handled
	# by other scripts if they need to do some ancilliary processing if 
	# redef-able consts are modified at runtime.
	event Control::configuration_update_response();
	}
	
event Control::shutdown_request()
	{
	# Send the acknowledgement event.
	event Control::shutdown_response();
	# Schedule the shutdown to let the current event queue flush itself first.
	event terminate_event();
	}
