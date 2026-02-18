# @TEST-DOC: Ensures we can suppress timeouts
# 
# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/retransmit-timeout.pcap %INPUT >out
#
# @TEST-EXEC: btest-diff out

@load base/protocols/conn

redef tcp_inactivity_timeout = 10sec;

global current_suppressions = 0;
const num_suppressions = 3;

hook connection_timing_out(c: connection)
	{
	if ( current_suppressions < num_suppressions )
		{
		print fmt("Suppressed the timeout for connection %s %d time(s)", c$uid, current_suppressions + 1);
		current_suppressions += 1;
		break;
		}
	}

event connection_timeout(c: connection)
	{
	# Ensure that this connection was alive for less than one timeout interval,
	# despite getting suppressed
	assert(c$duration < tcp_inactivity_timeout);
	}
