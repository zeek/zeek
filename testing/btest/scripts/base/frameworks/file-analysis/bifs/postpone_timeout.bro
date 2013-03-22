# @TEST-EXEC: btest-bg-run bro bro -r $TRACES/http/206_example_b.pcap $SCRIPTS/file-analysis-test.bro %INPUT
# @TEST-EXEC: btest-bg-wait 8
# @TEST-EXEC: btest-diff bro/.stdout

global cnt: count = 0;
global timeout_cnt: count = 0;

redef FileAnalysis::default_timeout_interval=2sec;

redef test_file_analysis_source = "HTTP";

redef test_get_file_name = function(info: FileAnalysis::Info): string
	{
	local rval: string = fmt("%s-file%d", info$file_id, cnt);
	++cnt;
	return rval;
	};

redef exit_only_after_terminate = T;

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	{
	if ( trig != FileAnalysis::TRIGGER_TIMEOUT ) return;

	if ( timeout_cnt < 1 )
		FileAnalysis::postpone_timeout(info$file_id);
	else
		terminate();
	++timeout_cnt;
	}
