# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/retransmit-timeout.pcap %INPUT
# @TEST-EXEC: mv conn.log conn-limited.log

# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/retransmit-timeout.pcap %INPUT max_timer_expires=0
# @TEST-EXEC: mv conn.log conn-all.log


# @TEST-EXEC: btest-diff conn-limited.log
# @TEST-EXEC: btest-diff conn-all.log

@load base/protocols/conn

const max_timer_expires_default = max_timer_expires;

event dummy()
	{
	}

event network_time_init()
	{
	# Suppress connection timeout by scheduling more timers than
	# can be handled in the context of a single packet, by default.
	local i = 0;
	while ( ++i <= max_timer_expires_default )
		schedule 4 min { dummy() };
	}
