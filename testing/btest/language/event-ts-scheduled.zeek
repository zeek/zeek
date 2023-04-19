# @TEST-EXEC: zeek -b -r $TRACES/ticks-dns-1hr.pcap %INPUT > out
# @TEST-EXEC: btest-diff out

global runs = 0;

event test(schedule_time: time)
	{
	print fmt("[%D] Test was scheduled at %D for %D", network_time(),
		schedule_time, current_event_time());
	}

event new_connection(c: connection)
	{
	local nt = network_time();
	print fmt(">> Run %s (%D)", runs, nt);
	schedule 30 mins { test(nt) };
	schedule 15 mins { test(nt) };
	print fmt("<< Run %s (%D)", runs, nt);
	++runs;
	}
