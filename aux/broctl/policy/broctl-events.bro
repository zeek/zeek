# $Id: broctl-events.bro 6903 2009-09-04 23:34:56Z robin $
#
# Events which are sent by broctl.

module BroCtl;

global sh_log = open_log_file("broctl") &disable_print_hook;

event bro_init()
	{
	set_buf(sh_log, F);
	}

# Request the value of an ID. 
# (This is copied from remote-print-id-reply.bro for completeness here.)
event request_id_response(id: string, val: string)
	{
	print sh_log, fmt("%.6f raised event request_id_response(%s, %s)", network_time(), id, val);
	}

event request_id(id: string)
	{
	print sh_log, fmt("%.6f got event request_id(%s)", network_time(), id);

	local val = lookup_ID(id);
	event request_id_response(id, fmt("%s", val));
	}

@load remote

# Returns the current communication status (one line per connected peer).
event get_peer_status_response(s: string)
	{
	print sh_log, fmt("%.6f raised event get_peer_status(%s)", network_time(), s);
	}

event get_peer_status()
	{
	print sh_log, fmt("%.6f got event get_peer_status()", network_time());
	
	local status = "";
	
	for ( p in Remote::destinations )
		{
		local peer = Remote::destinations[p];
		if ( ! peer$connected )
			next;
		
		status += fmt("peer=%s host=%s events_in=? events_out=? ops_in=? ops_out=? bytes_in=? bytes_out=?\n",
					  peer$peer$descr, peer$host);
		}
	
	event get_peer_status_response(status);
	}

# Returns net_stats.

global last_cstat: net_stats;
global last_cstat_time: time;

event net_stats_update(t: time, ns: net_stats)
	{
	last_cstat = ns;
	last_cstat_time = t;
	}

event get_net_stats_response(s: string)
	{
	print sh_log, fmt("%.6f raised event get_net_stats_response(%s)", network_time(), s);
	}

event get_net_stats()
	{
	local reply = fmt("%.6f recvd=%d dropped=%d link=%d\n", last_cstat_time, 
				  last_cstat$pkts_recvd, last_cstat$pkts_dropped, last_cstat$pkts_link);
	event get_net_stats_response(reply);
	}


