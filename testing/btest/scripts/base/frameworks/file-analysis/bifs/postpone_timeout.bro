# @TEST-EXEC: btest-bg-run bro bro -r $TRACES/http/206_example_b.pcap $SCRIPTS/file-analysis-test.bro %INPUT
# @TEST-EXEC: btest-bg-wait 8
# @TEST-EXEC: btest-diff bro/.stdout

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

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, f: fa_file)
	{
	if ( trig != FileAnalysis::TRIGGER_NEW ) return;

	f$timeout_interval=2sec;
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, f: fa_file)
	{
	if ( trig != FileAnalysis::TRIGGER_TIMEOUT ) return;

	if ( timeout_cnt < 1 )
		FileAnalysis::postpone_timeout(f);
	else
		terminate();
	++timeout_cnt;
	}
