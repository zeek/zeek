# @TEST-EXEC: zeek -C -r $TRACES/tcp/retransmit-timeout.pcap %INPUT
# @TEST-EXEC: mv conn.log conn-limited.log

# @TEST-EXEC: zeek -C -r $TRACES/tcp/retransmit-timeout.pcap %INPUT expire_all_timers=T
# @TEST-EXEC: mv conn.log conn-all.log


# @TEST-EXEC: btest-diff conn-limited.log
# @TEST-EXEC: btest-diff conn-all.log

event dummy()
	{
	}

event network_time_init()
	{
	# Suppress connection timeout by scheduling more timers than
	# can be handled in the context of a single packet.
	local i = 0;
	while ( ++i <= max_timer_expires )
		schedule 4 min { dummy() };
	}
