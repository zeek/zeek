# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff stats.log

@load policy/misc/stats

event zeek_init()
	{
	# Various fields will be unstable for use in baseline, so use one that is.
	local filter: Log::Filter = [$name="pkt-stats", $include=set("pkts_proc")];
	Log::remove_filter(Stats::LOG, "default");
	Log::add_filter(Stats::LOG, filter);
	}
