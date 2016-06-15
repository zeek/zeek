# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -m -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

@load policy/misc/stats.bro

event load_sample(samples: load_sample_info, CPU: interval, dmem: int)
	{
	print CPU;
	}
