# @TEST-DOC: A connection with history ShADadtFRfr (resets after fins) would expire only after tcp_inactivity_timeout (5mins) instead of tcp_reset_delay (5s) when no connection_reset() handler was implemented. Test this via exit_only_after_terminate=T and set_network_time() trickery.
#
# @TEST-EXEC: zeek -b -r $TRACES/postgresql/psql-aws-ssl-require.pcap %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff out
# @TEST-EXEC: btest-diff-cut -m conn.log

@load base/protocols/conn

redef exit_only_after_terminate = T;

# Not implementing this handler previously resulted in ResetTimer()
# never running. Only here for documentation purposes.
# event connection_reset(c: connection)
#	{
#	print network_time(), "reset", c$uid;
#	}

event Pcap::file_done(path: string)
	{
	print network_time(), "Pcap::file_done";
	set_network_time(network_time() + tcp_reset_delay + 0.1sec);
	}

event connection_state_remove(c: connection)
	{
	print network_time(), "remove", c$uid;
	terminate();
	}
