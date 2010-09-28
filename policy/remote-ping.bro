# $Id: remote-ping.bro 2704 2006-04-04 07:35:46Z vern $
#
# Exchanges periodic pings between communicating Bro's to measure their
# processing times.

@load remote

module RemotePing;

export {
	const ping_interval = 1 secs;
}

global pings: table[event_peer] of count;

event remote_connection_established(p: event_peer)
	{
	pings[p] = 0;
	}

event remote_connection_closed(p: event_peer)
	{
	delete pings[p];
	}

event ping()
	{
	for ( p in pings )
		send_ping(p, ++pings[p]);

	schedule ping_interval { ping() };
	}

event remote_pong(p: event_peer, seq: count,
			d1: interval, d2: interval, d3: interval)
	{
	# We log three times: "time=<t1> [<t2>/<t3>]"
	#    t1: round-trip between the two parent processes.
	#    t2: round-trip between the two child processes.
	#    t3: sum of time spent in client<->parent communication on
	#	 either side
	Remote::do_script_log(p, fmt("ping seq=%d time=%.3fs [%.3fs/%.3fs]", seq,
				d1, d2 - d3, d1 - d2 + d3));
	}

event bro_init()
	{
	schedule ping_interval { ping() };
	}
