# @TEST-DOC: Ensure network_time_init fires on wallclock fallback.
#
# @TEST-EXEC: btest-bg-run zeek "zeek -b %INPUT >output"
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/output

redef exit_only_after_terminate = T;

event network_time_init()
	{
	print "network_time_init";
	terminate();
	}
