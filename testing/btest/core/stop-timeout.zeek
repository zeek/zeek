# @TEST-DOC: Ensures we can suppress timeouts
#
# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/timeout-with-pings.pcap %INPUT 2>&1
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/conn

redef tcp_inactivity_timeout = 10sec;

global last_timeout_attempt: time = 0;
global current_suppressions = 0;

hook connection_timing_out(c: connection)
	{
	print fmt("Checking for timeout at %T", network_time());
	print fmt("Suppressed the timeout for connection %s %d time(s)", c$uid,
	    current_suppressions + 1);

	# Ensure each one waits at least tcp_inactivity_timeout
	if ( last_timeout_attempt != 0 )
		assert last_timeout_attempt + tcp_inactivity_timeout <= network_time();

	last_timeout_attempt = network_time();

	current_suppressions += 1;
	break;
	}

event connection_timeout(c: connection)
	{
	# Ensure that this connection was alive for less than one timeout interval,
	# despite getting suppressed
	assert ( c$duration < tcp_inactivity_timeout );
	}
