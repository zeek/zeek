# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace %INPUT

@load policy/misc/stats

event load_sample(samples: load_sample_info, CPU: interval, dmem: int)
	{
	# This output not part of baseline as it varies, but guess this test
	# should still exist to cover potential memory leaks.
	print CPU;
	}
