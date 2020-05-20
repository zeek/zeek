# @TEST-EXEC: btest-bg-run zeek zeek -r $TRACES/http/206_example_b.pcap $SCRIPTS/file-analysis-test.zeek %INPUT
# @TEST-EXEC: btest-bg-wait 8
# @TEST-EXEC: btest-diff zeek/.stdout

global cnt: count = 0;
global timeout_cnt: count = 0;

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(f: fa_file): string
	{
	local rval: string = fmt("%s-file%d", f$id, cnt);
	++cnt;
	return rval;
	};

redef exit_only_after_terminate = T;
redef default_file_timeout_interval = 2sec;

event file_timeout(f: fa_file)
	{
	if ( timeout_cnt < 1 )
		Files::set_timeout_interval(f, f$timeout_interval);
	else
		terminate();
	++timeout_cnt;
	}
